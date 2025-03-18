import pandas as pd
import pickle
import json
import sys
import os
sys.path.append("utils")
sys.path.append("llm_prompt")

from llm import classify_vuln
import gpu_utils
import logging

cot_prompt = """You are a security expert tasked with identifying vulnerabilities in a given code. Carefully analyze the code using CWE (Common Weakness Enumeration) descriptions and determine if it contains any vulnerabilities step by step.
For each step:
1. Examine overall the structure of the code to understand its purpose and functionality.
2. Assess User Input Handling & Data Flow. Determine how inputs are received and processed (e.g., user input, file input, API request). Track data flow to check if input validation/sanitization is missing or insufficient.
3. Analyze the code to check if it contains any vulnerabilities.
  - If a vulnerability is identified, proceed to steps 4–7.
  - If no vulnerabilities are found, the output must be strictly:
{
  "is_this_vuln": False,
  "vuln_code_part": None,
  "reason": "Detailed explanation of why the code is safe.",
  "cwe": None
} 

4. Identify the name of function in the code that could be exploited. You can refer to the function name or the code snippet that could be exploited. 
5. Explain why the identified area might be vulnerable, providing a detailed explanation referencing CWE descriptions.
6. Based on the analysis, identify the CWE category and include its ID, name, and description.
7. Respond only with the following JSON format.

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

Now analyse the code provided and respond accordingly:
"""

fs_prompt = """You are a security expert tasked with identifying vulnerabilities in a given code. Carefully analyze the code using CWE (Common Weakness Enumeration) descriptions step by step.
Example 1: Vulnerable Code
$userName = $_POST["user"];
$command = 'ls -l /home/' . $userName;
system($command);

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "$command = 'ls -l /home/' . $userName;",
  "reason": "The $userName variable is not checked for malicious input. An attacker could set the $userName variable to an arbitrary OS command such as: ;rm -rf /",
  "cwe": {
    "cwe_id": "CWE-74",
    "name": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "description": "The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component."
  }
}

Example 2: Vulnerable Code
my $q = new CGI;

if ($q->cookie('loggedin') ne "true") {
if (! AuthenticateUser($q->param('username'), $q->param('password'))) {
ExitError("Error: you need to log in first");
}
else {
# Set loggedin and user cookies.
$q->cookie(
-name => 'loggedin',
-value => 'true'
);

$q->cookie(
-name => 'user',
-value => $q->param('username')
);
}
}

if ($q->cookie('user') eq "Administrator") {
DoAdministratorTasks();
}

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "f ($q->cookie('user') eq "Administrator") {";",
  "reason": "The following code intends to ensure that the user is already logged in. If not, the code performs authentication with the user-provided username and password. If successful, it sets the loggedin and user cookies to "remember" that the user has already logged in. Finally, the code performs administrator tasks if the logged-in user has the "Administrator" username, as recorded in the user cookie. Unfortunately, this code can be bypassed. The attacker can set the cookies independently so that the code does not check the username and password.",
  "cwe": {
    "cwe_id": "CWE-287",
    "name": "Improper Authentication",
    "description": "When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct."
  }
}

Example 3: Vulnerable Code
int writeDataFromSocketToFile(char *host, int port)
{

char filename[FILENAME_SIZE];
char buffer[BUFFER_SIZE];
int socket = openSocketConnection(host, port);

if (socket < 0) {
printf("Unable to open socket connection");
return(FAIL);
}
if (getNextMessage(socket, filename, FILENAME_SIZE) > 0) {
if (openFileToWrite(filename) > 0) {
while (getNextMessage(socket, buffer, BUFFER_SIZE) > 0){
if (!(writeToFile(buffer) > 0))
break;
}
}
closeFile();
}
closeSocket(socket);
}

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "while (getNextMessage(socket, buffer, BUFFER_SIZE) > 0){ if (!(writeToFile(buffer) > 0)) break; }",
  "reason": "This example creates a situation where data can be dumped to a file on the local file system without any limits on the size of the file. This could potentially exhaust file or disk resources and/or limit other clients' ability to access the service.",
  "cwe": {
    "cwe_id": "CWE-400",
    "name": "Uncontrolled Resource Consumption",
    "description": "The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources."
  }
}

Example 4: Vulnerable Code
UINT errCode = WinExec( "C:\\Program Files\\Foo\\Bar", SW_SHOW );

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "UINT errCode = WinExec( "C:\\Program Files\\Foo\\Bar", SW_SHOW );",
  "reason": "The code uses the WinExec function to execute a command. WinExec is a legacy function that is not safe and can be exploited by an attacker to run arbitrary commands on the system.",
  "cwe": {
    "cwe_id": "CWE-428",
    "name": "Unquoted Search Path or Element",
    "description": "The product uses a search path that contains an unquoted element, in which the element contains whitespace or other separators. This can cause the product to access resources in a parent path."
  }
}

Response 5: Vulnerable Code
public static final double price = 20.00;
int quantity = currentUser.getAttribute("quantity");
double total = price * quantity;
chargeUser(total);

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "int quantity = currentUser.getAttribute("quantity");",
  "reason": "The code does not validate the input quantity, which can be manipulated by an attacker to perform a business logic attack. This can lead to undercharging or overcharging the user.",
  "cwe": {
    "cwe_id": "CWE-20",
    "name": "Improper Input Validation",
    "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."
  }
}

Example 6: Non-vulnerable Code
func serve(w http.ResponseWriter, r *http.Request) {
  var body []byte
  const MaxRespBodyLength = 1e6
  if r.Body != nil {
    r.Body = http.MaxBytesReader(w, r.Body, MaxRespBodyLength)
    if data, err := io.ReadAll(r.Body); err == nil {
      body = data
    }
  }
}

Response:
{
  "is_this_vuln": false,
  "vuln_code_part": None,
  "reason": "The code prevents resource exhaustion by limiting the maximum request body size using http.MaxBytesReader. This ensures that malicious clients cannot send excessively large payloads that could consume system memory and cause service disruptions.",
  "cwe": None
}

Now analyse the code provided and respond accordingly:
"""

SYSTEM_PROMPT = "You are a highly skilled code analysis assistant specialized in identifying security vulnerabilities in software code."

def main():
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
  
  logging.info("Loading non-vulnerable code pickle file.")
  with open(f"./dataset/new_test/test_non_vuln.pkl", "rb") as f:
    non_vuln = pickle.load(f)
  
  logging.info("Loading vulnerable code pickle file.")
  with open(f"./dataset/new_test/test_vuln.pkl", "rb") as f:
    vuln = pickle.load(f)
  
  for prompt_temp, prompt_type in zip([cot_prompt, fs_prompt], ['cot_prompt', 'fs_prompt']):
    for df, code_type in zip([non_vuln, vuln], ['non_vuln_code', 'vuln_code'], ):
      logging.info(f"Classifying {code_type}.")
      os.makedirs(f'./result/rag_{prompt_type}', exist_ok=True)
      results = classify_vuln(df, SYSTEM_PROMPT, code_type, prompt_temp, prompt_type, rag_step=True)
      
      logging.info(f"Saving results for {code_type}.")
      with open(f"./result/rag_{prompt_type}/{code_type}_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
      
      logging.info(f"Sleeping for 5 minutes to manage GPU usage.")
      gpu_utils.sleep_for_minutes(5)
        
    

if __name__ == "__main__":
    main()
