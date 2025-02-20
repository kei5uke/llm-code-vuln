import ollama
from typing import Union
from pydantic import BaseModel
import json
import logging
import sys
import time
import tiktoken
sys.path.append("utils")

import gpu_utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ClassifyTemplate(BaseModel):
  cwe_id: str
  name: str
  description: str

class ResponseTemplate(BaseModel):
  is_this_vuln: bool
  vuln_code_part: Union[str, None]
  reason: Union[str, None]
  cwe: Union[ClassifyTemplate, None]

models = ['llama3.1:8b', 'codellama:7b', 'phi4:14b', 'deepseek-r1:14b']


def classify_vuln(df, code_type, prompt_temp, prompt_type):
    results_to_insert = []
    total_samples = len(df) * len(models)
    save_interval = 10  # Save every 10%
    next_save_point = save_interval  # Start at 10%

    start_time = time.perf_counter()  # Track the start time

    for i in range(len(df)):
        file_change_id = None
        version = 1
        error = False
        model_name = None
        result = None

        try:
            file_change_id = df.iloc[i]['file_change_id']
            vuln_type = df.iloc[i]['cwe_id'] if code_type == 'vuln_code' else 'non_vuln'
            code = df.iloc[i][code_type]
            # contest_length = df.iloc[i]['token_count'] + 1000
            context = prompt_temp + '\n' + code
            encoding = tiktoken.get_encoding("cl100k_base")
            token_count = len(encoding.encode(context)) + 500
            
            for m, model in enumerate(models):
                retry_attempts = 1
                for attempt in range(retry_attempts + 1):
                  try:
                    gpu_utils.free_gpu_memory()

                    # Calculate progress
                    sample_index = i * len(models) + m + 1
                    progress = (sample_index / total_samples) * 100

                    logger.info(f'[Progress] {code_type} | {token_count} tokens | {model} | {sample_index}/{total_samples} | {progress:.2f}%')
                    # start_time = gpu_utils.pause_if_needed(start_time)
                    start_time_model = time.perf_counter()

                    response = ollama.chat(
                      model=model, 
                      messages=[{"role": "user", "content": context}],
                      options={
                        "temperature": 0,
                        "num_ctx": token_count,
                      },
                      format=ResponseTemplate.model_json_schema()
                    )
                    
                    end_time_model = time.perf_counter()


                    result = json.loads(response['message']['content'])
                    
                    model_name = model
                    
                    results_to_insert.append({
                      'file_change_id': file_change_id,
                      'vuln_type': vuln_type,
                      'result': result,
                      'model': model_name,
                      'version': version,
                      'error': error,
                      'time': end_time_model - start_time_model
                    })

                    logger.info(f'[Progress] Time: {end_time_model - start_time_model:.2f}s')

                    # Save progress at each 10% milestone
                    if progress >= next_save_point:
                      with open(f'./result/{prompt_type}/progress_{code_type}_{int(next_save_point)}.json', 'w') as f:
                        json.dump(results_to_insert, f, indent=4)
                      logger.info(f'Saved progress at {next_save_point}%')
                      next_save_point += save_interval  # Increment to the next save point
                    
                    break  # Exit retry loop if successful

                  except Exception as e:
                    logger.error(f'Attempt {attempt + 1} failed: {e}')
                    if attempt == retry_attempts:
                      error = True
                      results_to_insert.append({
                        'file_change_id': file_change_id,
                        'vuln_type': vuln_type,
                        'result': result,
                        'model': model_name,
                        'version': version,
                        'error': error,
                        'time': None
                      })
                    

        except Exception as e:
            error = True
            logger.error(f'Something went wrong: {e}')
            results_to_insert.append({
                'file_change_id': file_change_id,
                'vuln_type': vuln_type,
                'result': result,
                'model': model_name,
                'version': version,
                'error': error,
                'time': None
            })

        finally:
            gpu_utils.free_gpu_memory()
            
    return results_to_insert