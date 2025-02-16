import pandas as pd
import pickle
import json
import sys
sys.path.append("utils")
sys.path.append("llm_prompt")

from llm import classify_vuln
import gpu_utils
import logging

def main():
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
  
  logging.info("Loading non-vulnerable code pickle file.")
  with open(f"./dataset/test_pickles/test_non_vuln.pkl", "rb") as f:
    non_vuln = pickle.load(f)
  
  logging.info("Loading vulnerable code pickle file.")
  with open(f"./dataset/test_pickles/test_vuln.pkl", "rb") as f:
    vuln = pickle.load(f)
  
  for df, code_type in zip([non_vuln, vuln], ['non_vuln_code', 'vuln_code']):
    logging.info(f"Classifying {code_type}.")
    results = classify_vuln(df, code_type)
    
    logging.info(f"Saving results for {code_type}.")
    with open(f"./result/{code_type}_results.json", "w", encoding="utf-8") as f:
      json.dump(results, f, indent=4, ensure_ascii=False)
    
    logging.info(f"Sleeping for 5 minutes to manage GPU usage.")
    gpu_utils.sleep_for_minutes(5)
        
    

if __name__ == "__main__":
    main()