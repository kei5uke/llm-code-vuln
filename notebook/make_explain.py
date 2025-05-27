import pandas as pd
from openai import OpenAI

# Constants
# INPUT_PICKLE_PATH = '../dataset/file_level/train_df_file.pkl'
INPUT_PICKLE_PATH = '../dataset/func_level/train_df_func.pkl'

# OUTPUT_PICKLE_PATH = 'file_with_explanation.pkl'
OUTPUT_PICKLE_PATH = 'func_with_explanation.pkl'
API_KEY = ""

# Templates for prompts
VULN_TEMP = """Analyze the provided code and explain why it is vulnerable to the specified CWE-ID.
Your response should consist of only a concise explanation that clearly links the vulnerable behavior in the code to the characteristics of the CWE.
Do not include summaries, lists, or step-by-step breakdowns. Focus only on the reasoning.

CODE: {}
CWE_ID: {}
"""

NON_VULN_TEMP = """Analyze the provided code and explain why it is not vulnerable.
Your response should consist of only a concise explanation that justifies the code's security with respect to common vulnerabilities.
Do not include summaries or step-by-step breakdowns. Focus only on the reasoning and security measures present.

CODE: {}
"""

# CWE descriptions
CWES = {"CWE-79": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-89": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "CWE-434": "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "CWE-352": "CWE-352: Cross-Site Request Forgery (CSRF)"}


def main():
    # Initialize OpenAI client
    client = OpenAI(api_key=API_KEY)

    # Load and prepare data
    print("Loading dataset...")
    # df = pd.read_pickle(INPUT_PICKLE_PATH)
    # df = df.dropna()
    df = pd.read_pickle(OUTPUT_PICKLE_PATH)

    total_rows = len(df)
    print(f"Loaded {total_rows} rows to process\n")

    # Process each row
    # for index, row in df.iterrows():
    for index, row in df.iterrows():
        if pd.isnull(row['explanation']) or 'error' in str(row['explanation']).lower():
            current_row = index + 1
            label = CWES.get(row['label'], "None")

            # Print task information
            if label == "None":
                task_type = "Non-Vulnerable Analysis"
            else:
                task_type = f"Vulnerability Analysis ({label})"

            print(f"\n[{current_row}/{total_rows}] Starting {task_type}")
            print("="*50)

            if label == "None":
                prompt = NON_VULN_TEMP.format(row['code'])
                print("Analyzing non-vulnerable code...")
            else:
                prompt = VULN_TEMP.format(row['code'], label)
                print(f"Analyzing vulnerability: {label}...")

            # Get explanation from OpenAI
            try:
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.5
                )

                # Store explanation
                df.at[index, 'explanation'] = response.choices[0].message.content
                print(
                    f"Completed row {current_row}/{total_rows} successfully!")
                print("\nSaving results...")
                df.to_pickle(OUTPUT_PICKLE_PATH)

            except Exception as e:
                print(f"Error processing row {current_row}: {str(e)}")
                # df.at[index, 'explanation'] = f"Error: {str(e)}"

    # Save results
    print("\nSaving results...")
    df.to_pickle(OUTPUT_PICKLE_PATH)
    print(f"Processing complete! Results saved to {OUTPUT_PICKLE_PATH}")


if __name__ == "__main__":
    main()
