import pandas as pd
import pickle
import json
import sys
sys.path.append("utils")
sys.path.append("llm_prompt")

import llm

def main():
    with open(f"./dataset/test_pickles/test_non_vuln.pkl", "rb") as f:
      non_vuln = pickle.load(f)
    with open(f"./dataset/test_pickles/test_vuln.pkl", "rb") as f:
      vuln = pickle.load(f)
    
    for df, code_type in zip([non_vuln, vuln],['non_vuln_code', 'vuln_code']):
       results = llm.classify_vuln(df, code_type)
       with open(f"./result/{code_type}_results.json", "w", encoding="utf-8") as f:
          json.dump(results, f, indent=4, ensure_ascii=False)
        
    

if __name__ == "__main__":
    main()