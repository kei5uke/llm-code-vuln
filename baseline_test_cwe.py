import pandas as pd
import sqlite3 as lite
import ast
import json
import re
import time
import pickle
import ollama
import logging
import gc
from typing import Union
from pydantic import BaseModel


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

langs = ["PHP", "C", "JavaScript", "Python", "Java", "TypeScript", "C++", "Go", "Ruby", "Shell"]
remove_cwe = ['NVD-CWE-noinfo', 'NVD-CWE-Other']
cwe_top_25 = [
    "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", "CWE-416", "CWE-862", "CWE-434", 
    "CWE-94", "CWE-20", "CWE-77", "CWE-287", "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119", 
    "CWE-476", "CWE-798", "CWE-190", "CWE-400", "CWE-306"
]


def free_gpu_memory():
    gc.collect()

def create_connection(db_file):
  """
  create a connection to sqlite3 database
  """
  conn = None
  try:
    conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
  except Exception as e:
    logger.error(e)
  return conn

conn = create_connection('/home/keisuke/code/llm-code-vuln/dataset/CVEfixes_v1.0.8/Data/DB.db')

def pre_processing(df):
  # keep only the specified programming languages
  df = df[df['programming_language'].isin(langs)]

  # code diff: both add & del should exist
  df['diff_added'] = df.apply(lambda row: ast.literal_eval(row.diff_parsed)['added'], axis=1)
  df['diff_deleted'] = df.apply(lambda row: ast.literal_eval(row.diff_parsed)['deleted'], axis=1)
  df = df[df['diff_added'].apply(bool) & df['diff_deleted'].apply(bool)] 
  df = df.reset_index(drop=True)
  df = df.drop(columns=['diff_parsed'])

  # cve description type str -> arr
  def parse_py_literal(text):
    if not isinstance(text, str):
      return text
    try:
      return ast.literal_eval(text)
    except (SyntaxError, ValueError):
      return None

  df['cve_description'] = df['cve_description'].apply(parse_py_literal)
  
  # code before and after
  df = df[df['vuln_code'].notna()]
  df = df[df['vuln_code'] != 'None']
  df = df[df['non_vuln_code'].notna()]
  df = df[df['non_vuln_code'] != 'None']
  
  # remove rows where number of lines in the code is below 30
  for col in ['vuln_code', 'non_vuln_code']:
    df[f'{col}_num_lines'] = df[col].apply(
      lambda x: x.count('\n') + 1 if isinstance(x, str) else 0
    )
    df = df[df[f'{col}_num_lines'] >= 30]

  # remove empty list in diff_deleted
  df = df[df['diff_deleted'].apply(lambda x: isinstance(x, list) and len(x) > 0)]

  # token_count should be num
  df['token_count'] = df['token_count'].apply(parse_py_literal)
  df = df.dropna(subset=['token_count'])
  df['token_count'] = pd.to_numeric(df['token_count'])
  
  # drop the other CWE
  df = df[~df["cwe_id"].isin(remove_cwe)]
  
  df = df.dropna()
  
  return df

def pick_samples(df):
  sample_size = 20
  
  # Sample the data
  random_samples = df.sample(n=sample_size, random_state=123)

  if len(random_samples) < sample_size:
    logger.info(f"Not enough samples")
    return None

  return random_samples

class ClassifyTemplate(BaseModel):
  cwe_id: str
  name: str
  description: str

class ResponseTemplate(BaseModel):
  is_this_vuln: bool
  vuln_code_part: Union[str, None]
  reason: Union[str, None]
  cwe: Union[ClassifyTemplate, None]

prompt = """
You are a security expert tasked with identifying vulnerabilities in a given code. Carefully analyze the code using CWE (Common Weakness Enumeration) descriptions step by step.

For each step:

1. Analyze the code to check if it contains any vulnerabilities.
  - If a vulnerability is identified, proceed to steps 2–4.
  - If no vulnerabilities are found, the output must be strictly: {"vulnerabilities": null}.
2. Identify the specific area in the code that could be exploited.
3. Explain why the identified area might be vulnerable, providing a detailed explanation referencing CWE descriptions.
4. Based on the analysis, identify the CWE category and include its ID, name, and description.
5. Respond only with the following JSON format.

Output Requirements:
{
  "is_this_vuln": True,
  "vuln_code_part": "the code snippet that could be exploited.",
  "reason": "Detailed explanation of why the code is vulnerable.",
  "cwe": {
    "cwe_id": "CWE-XXX",
    "name": "Name of the CWE category",
    "description": "Brief description of the CWE category."
  }
}
"""

models = ['llama3.1:8b', 'codellama:13b', 'phi4:latest']

def llm_classify(df):
    results_to_insert = []
    total_samples = len(df) * 2 * len(models)

    for s in range(len(df)):
        for code_type in ['vuln_code', 'non_vuln_code']:
            file_change_id = None
            true_vuln = None
            version = 1
            error = False
            model_name = None
            result = None
            try:
                file_change_id = df.iloc[s]['file_change_id']
                true_vuln = True if code_type == 'vuln_code' else False
                actual_cwe = df.iloc[s]['cwe_id'] if code_type == 'vuln_code' else None
                code = df.iloc[s][code_type]
                context = prompt + '\n Code: \n' + code
                
                for m, model in enumerate(models):
                    # Log progress
                    sample_index = s + ((1 if code_type == 'non_vuln_code' else 0) * len(df)) + (m + 1) + 1
                    progress = (sample_index / total_samples) * 100
                    logger.info(f'[Progress] {code_type} | {model} | {sample_index}/{total_samples} | {progress:.2f}%')

                    start_time = time.perf_counter()
                    
                    response = ollama.chat(
                        model=model, 
                        messages=[{"role": "user", "content": context}],
                        options={"temperature": 0},
                        format=ResponseTemplate.model_json_schema()
                    )
                    
                    end_time = time.perf_counter()
                    result = json.loads(response['message']['content'])
                    
                    model_name = model
                    
                    results_to_insert.append({
                        'file_change_id': file_change_id,
                        'true_vuln': true_vuln,
                        'actual_cwe': actual_cwe,
                        'result': result,
                        'model': model_name,
                        'version': version,
                        'error': error,
                        'time': end_time - start_time
                    })

            except Exception as e:
                error = True
                logger.error(f'Something went wrong: {e}')
                results_to_insert.append({
                    'file_change_id': file_change_id,
                    'true_vuln': true_vuln,
                    'actual_cwe': actual_cwe,
                    'result': result,
                    'model': model_name,
                    'version': version,
                    'error': error,
                    'time': None
                })

            finally:
                free_gpu_memory()
            
    return results_to_insert

def purify_results(results):
  # filter CWE-num only
  for result in results:
    cwe = result['result']['cwe']
    if cwe is not None:
      cwe_string = cwe['cwe_id']
      if 'CWE-' in cwe_string:
        match = re.search('CWE-\d+', cwe_string, re.IGNORECASE)
        if match:
          result['result']['cwe']['cwe_id'] = match.group()
        else:
          result['result']['cwe']['cwe_id'] = None
  return results

def main():
  for l, cwe_id in enumerate(cwe_top_25):
    logger.info(f'[Log] {l+1}/{len(cwe_top_25)}|CWE_ID:{cwe_id}')
    query = f"""
      SELECT
        file_change.file_change_id,
        file_change.programming_language,
        cwe.cwe_id,
        cwe.cwe_name,
        file_change.code_after AS non_vuln_code,
        file_change.code_before AS vuln_code,
        cwe.description AS cwe_description,
        file_change.diff_parsed,
        cve.description AS cve_description,
        file_change.token_count
      FROM file_change
        INNER JOIN fixes
          ON file_change.hash = fixes.hash
        INNER JOIN cve
          ON fixes.cve_id = cve.cve_id
        INNER JOIN cwe_classification
          ON cve.cve_id = cwe_classification.cve_id
        INNER JOIN cwe
          ON cwe_classification.cwe_id = cwe.cwe_id
      WHERE
        cwe.cwe_id = '{cwe_id}'
        AND file_change.programming_language IS NOT NULL
        AND cwe.cwe_id IS NOT NULL
        AND cwe.cwe_name IS NOT NULL
        AND file_change.code_before IS NOT NULL
        AND cwe.description IS NOT NULL
        AND file_change.diff_parsed IS NOT NULL
        AND cve.description IS NOT NULL
        AND file_change.token_count IS NOT NULL;
      """
    df = pd.read_sql(query, con=conn)
    if len(df) <= 100: 
      logger.info(f'[INFO] {cwe_id} will be skipped')
      break
    
    df = pre_processing(df)
    df = pick_samples(df)
    results = llm_classify(df)
    results = purify_results(results)
    
    with open(f'./baseline_by_cwe/Baseline_{cwe_id}.pkl', 'wb') as f:
      pickle.dump(results, f)
    
    # break # for testing


if __name__ == '__main__':
  main()