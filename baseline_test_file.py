from datetime import datetime
import logging
import pandas as pd
import pickle
import json
import os

from tools.llm_tools.baseline_flow import classify_vuln
import tools.utils.gpu_utils as gpu_utils
from variables import SYSTEM_PROMPT, ZERO_PROMPT, COT_PROMPT, FS_PROMPT, MODELS


def main():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info("Loading non-vulnerable code pickle file.")
    # TODO: Create df contains both vulnerable and non-vulnerable code
    with open(f"./dataset/file_level/test_df_file.pkl", "rb") as f:
        df = pickle.load(f)

    timestamp = datetime.now().strftime("%m-%d_%H-%M")
    for model in MODELS:
        for prompt_template, prompt_type in zip([ZERO_PROMPT, COT_PROMPT, FS_PROMPT], ['zero_prompt', 'cot_prompt', 'fs_prompt']):
            logging.info(f"Start processing {prompt_type} with {model}.")
            save_dir_name = f"{timestamp}_{prompt_type}"
            folder_path = f"./result/{save_dir_name}"
            os.makedirs(folder_path, exist_ok=True)

            results = classify_vuln(
                df, SYSTEM_PROMPT, prompt_template, prompt_type, model, save_dir_name)

            logging.info(f"Saving final results.")
            tmp = 'FT_file_explain_simple'
            with open(f"{folder_path}/final_results_{tmp}.json", "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)

            logging.info(f"Sleeping for 5 minutes to manage GPU usage.")
            # gpu_utils.sleep_for_minutes(5)


if __name__ == "__main__":
    main()
