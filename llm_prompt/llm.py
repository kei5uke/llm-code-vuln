import ollama
import json
import logging
import sys
import time
import multiprocessing
import tiktoken
from typing import Union
from pydantic import BaseModel
from pymilvus import Collection

sys.path.append("utils")
sys.path.append("rag_tools")
import gpu_utils
import query_rag

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define Pydantic models for structured responses
class ClassifyTemplate(BaseModel):
    cwe_id: str
    name: str
    description: str

class ClassificationTemplate(BaseModel):
    is_this_vuln: bool
    vuln_code_part: Union[str, None]
    reason: Union[str, None]
    cwe: Union[ClassifyTemplate, None]

class RagQueryTemplate(BaseModel):
    code_function: str
    input_handling: str
    data_flow: str
    search_query: str

# Constants
#MODELS = ['llama3.1:8b', 'codellama:7b', 'phi4:14b', 'deepseek-r1:14b']
MODELS = ['hf.co/Kei5uke/llama3_30_epoch:latest', 'hf.co/Kei5uke/codellama_30_epoch:latest', 'hf.co/Kei5uke/phi4_30_epoch:latest', 'hf.co/Kei5uke/deepseek_30_epoch:latest']

TIMEOUT = 180  # 3 minutes
SAVE_INTERVAL = 10  # Save progress every 10%
ANALYSIS_PROMPT = """Analyze the following code snippet and perform the following tasks:
1. Analyze the Code Function:
  - Describe the purpose of the code.
  - Identify the main functionality or operation being performed.
2. Analyze the Code Input Handling:
  - Identify how inputs are received, processed, or validated.
  - Highlight any potential issues with input handling, such as lack of validation, sanitization, or improper use of sensitive data.
3. Analyze the Data Flow:
  - Trace the flow of data through the code.
  - Identify where sensitive data is stored, transmitted, or used.
  - Highlight any potential risks in the data flow, such as exposure to unauthorized access or improper storage.
4. Generate a Query String:
  - Based on the analysis, generate a concise search query that can be used to retrieve relevant CWE vulnerability information from RAG data.
  - The query should focus on the identified security issues, such as improper input handling, insecure data storage, or vulnerabilities related to the code's functionality.
  - The query should be in natural language and optimized for retrieving information from a document or knowledge base
5. Respond with the following JSON format:
{
  "code_function": "Description of the code's purpose and functionality",
  "input_handling": "Description of input handling and potential issues",
  "data_flow": "Description of data flow and potential risks",
  "search_query": "Generated natural language query for retrieving relevant CWE information from RAG data"
}
Code Snippet:
"""

EMBEDDING_MODEL = "mxbai-embed-large:335m"
RAG_COLLECTION_NAME = "rag_collection_demo_1"

query_rag.initialize_milvus_connection()
RAG_COLLECTION = Collection(RAG_COLLECTION_NAME)

# Helper Functions
def log_progress(code_type, token_count, model, sample_index, total_samples):
    """Log the progress of processing."""
    progress = (sample_index / total_samples) * 100
    logger.info(
        f"[Progress] {code_type} | {token_count} tokens | {model} | "
        f"{sample_index}/{total_samples} | {progress:.2f}%"
    )
    return progress

def calculate_token_length(prompt):
    """Calculate the token length of a prompt using tiktoken."""
    encoding = tiktoken.get_encoding("cl100k_base")
    return len(encoding.encode(prompt))

def call_ollama(model, system_prompt, user_prompt, prompt_type="classification"):
    """Call the Ollama API with a timeout."""
    queue = multiprocessing.Queue()
    
    def api_call(q):
        try:
            format = ClassificationTemplate if "classification" in prompt_type else RagQueryTemplate
            response = ollama.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0, "num_ctx": calculate_token_length(system_prompt + user_prompt) + 500},
                format=format.model_json_schema()
            )
            try:
                response = json.loads(response["message"]["content"])
            except Exception as e:
                logger.error(f"JSON parsing failed: {e}")
                q.put({"error": f"JSON parsing failed: {e}"})
                return

            q.put(response)
        except Exception as e:
            q.put({"error": str(e)})

    try:
        process = multiprocessing.Process(target=api_call, args=(queue,))
        process.start()
        process.join(timeout=TIMEOUT)

        if process.is_alive():
            process.terminate()
            process.join()
            return {"error": f"Ollama API call timed out after {TIMEOUT} seconds"}

        return queue.get() if not queue.empty() else {"error": "No response from API"}
    except Exception as e:
        logger.error(f"Process creation/execution failed: {e}")
        return {"error": f"Process creation/execution failed: {e}"}
    finally:
        queue.close()  # Ensure the queue is closed

def process_rag_step(model, system_prompt, code):
    """Process the RAG step for a given model."""
    rag_prompt = ANALYSIS_PROMPT + code + "\nJSON:\n"
    response = call_ollama(model, system_prompt, rag_prompt, prompt_type="rag")
    if "error" in response:
        logger.error(f"[Error] Rag: {response['error']}")
        return None

    rag_result = response
    if rag_result.get("search_query", "") != "":
        try:
            rag_context = query_rag.query_milvus(RAG_COLLECTION, rag_result["search_query"], EMBEDDING_MODEL)
            return rag_context, rag_result
        except Exception as e:
            logger.error(f"[Error] Milvus query failed: {e}")
            return None

    return None

def save_progress(results, prompt_type, code_type, progress, rag_step=False):
    """Save progress to a JSON file."""
    prompt_type = "rag_"+prompt_type if rag_step else prompt_type
    save_path = f"./result/{prompt_type}/progress_{code_type}_{int(progress)}.json"
    with open(save_path, "w") as f:
        json.dump(results, f, indent=4)
    logger.info(f"Saved progress at {progress}%")

def classify_vuln(df, system_prompt, code_type, prompt_temp, prompt_type, rag_step=False):
    """Classify vulnerabilities using the specified models."""
    results = []
    total_samples = len(df) * len(MODELS)
    next_save_point = SAVE_INTERVAL

    for i, row in df.iterrows():
        file_change_id = row.get("file_change_id")
        vuln_type = row["cwe_id"] if code_type == "vuln_code" else "non_vuln"
        code = row[code_type]
        user_prompt = prompt_temp + code

        for m, model in enumerate(MODELS):
            try:
                gpu_utils.free_gpu_memory()
                start_time = time.perf_counter()
                start_time = gpu_utils.pause_if_needed(start_time)

                sample_index = i * len(MODELS) + m + 1

                # Process RAG step if enabled
                rag_result = None  # Initialize to store the full RAG response
                rag_context = None  # Initialize to store only the RAG context
                user_prompt_with_context = user_prompt
                if rag_step:
                    rag_context, rag_result = process_rag_step(model, system_prompt, code)  # Store the full response
                    if rag_result and rag_context:
                        user_context = f"\nRetrieved Context:\n{rag_context}"
                        user_prompt_with_context = user_prompt + user_context

                token_count = calculate_token_length(system_prompt + user_prompt_with_context)
                progress = log_progress(code_type, token_count, model, sample_index, total_samples)

                # Call Ollama for classification
                # print("SYSTEM PROMPT: ", system_prompt)
                # print("USER PROMPT: ", user_prompt_with_context)
                response = call_ollama(model, system_prompt, user_prompt_with_context, prompt_type="classification")
                elapsed_time = time.perf_counter() - start_time

                # Prepare result entry
                result_entry = {
                    "file_change_id": file_change_id,
                    "vuln_type": vuln_type,
                    "result": response,
                    "model": model,
                    "version": 1,
                    "error": "error" in response,
                    "time": elapsed_time if "error" not in response else None,
                    "rag_response": rag_result,  # Store the full RAG response
                    "rag_context": rag_context  # Store only the RAG context (if needed)
                }

                results.append(result_entry)

                # Save progress periodically
                if progress >= next_save_point:
                    save_progress(results, prompt_type, code_type, next_save_point, rag_step=rag_step)
                    next_save_point += SAVE_INTERVAL
            except Exception as e:
                logger.error(f"[Error] Processing failed for model {model}, row {i}: {e}")
                continue  # Continue to the next iteration

    return results
