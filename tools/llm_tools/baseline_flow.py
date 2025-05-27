from tools.utils import gpu_utils
import ollama
import json
import logging
import sys
import time
import multiprocessing
import tiktoken
from typing import Union
from pydantic import BaseModel

from variables import SAVE_INTERVAL, TIMEOUT

sys.path.append("utils")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ClassifyTemplate(BaseModel):
    reasoning: str
    cwe_id: str


def log_progress(token_count, model, index, total_samples):
    """Log the progress of processing."""
    progress = (index / total_samples) * 100
    logger.info(
        f"[Progress] {token_count} tokens | {model} | "
        f"{index}/{total_samples} | {progress:.2f}%"
    )
    return progress


def save_progress(results, prompt_type, progress, save_dir_name):
    """Save progress to a JSON file."""
    save_path = f"./result/{save_dir_name}/progress_{int(progress)}_{prompt_type}.json"
    with open(save_path, "w") as f:
        json.dump(results, f, indent=4)
    logger.info(f"Saved progress at {progress}%")


def calculate_token_length(prompt):
    """Calculate the token length of a prompt using tiktoken."""
    encoding = tiktoken.get_encoding("cl100k_base")
    return len(encoding.encode(prompt))


def call_ollama(model, system_prompt, user_prompt):
    """Call the Ollama API with a timeout."""
    queue = multiprocessing.Queue()

    def api_call(q):
        try:
            response = ollama.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0, "num_ctx": calculate_token_length(
                    system_prompt + user_prompt) + 500},
                format=ClassifyTemplate.model_json_schema()
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


def classify_vuln(df, system_prompt, prompt_template, prompt_type, model, save_dir_name):
    """Classify vulnerabilities using the specified models."""
    results = []
    total_samples = len(df)
    next_save_point = SAVE_INTERVAL
    for index, row in df.iterrows():
        try:
            gpu_utils.free_gpu_memory()
            start_time = time.perf_counter()
            start_time = gpu_utils.pause_if_needed(start_time)
            sample_index = index + 1

            file_change_id = row.get("file_change_id")
            true_label = row["label"]
            code = row["code"]
            lang = row["programming_language"]
            user_prompt = prompt_template.format(code)
            token_count = calculate_token_length(system_prompt + user_prompt)
            progress = log_progress(
                token_count, model, sample_index, total_samples)

            response = call_ollama(
                model, system_prompt, user_prompt)
            elapsed_time = time.perf_counter() - start_time

            # Prepare result entry
            result_entry = {
                "index": index,
                "file_change_id": file_change_id,
                "lang": lang,
                "vuln_type": true_label,
                "result": response,
                "model": model,
                "version": 1,
                "error": "error" in response,
                "time": elapsed_time if "error" not in response else None,
            }

            results.append(result_entry)

            # Save progress periodically
            if progress >= next_save_point:
                save_progress(results, prompt_type,
                              next_save_point, save_dir_name)
                next_save_point += SAVE_INTERVAL

        except Exception as e:
            logger.error(
                f"[Error] Processing failed for model {model}, row {index}: {e}")
            continue  # Continue to the next iteration

    return results
