import pandas as pd
import pickle
import json
import sys
sys.path.append("utils")
sys.path.append("llm_prompt")

from llm import classify_vuln
import gpu_utils
import logging

cot_prompt = """
You are a security expert tasked with identifying vulnerabilities in a given code. Carefully analyze the code using CWE (Common Weakness Enumeration) descriptions and determine if it contains any vulnerabilities step by step.
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

Now analyse the code provided and respond accordingly.
code:
"""

fs_prompt = """
You are a security expert tasked with identifying vulnerabilities in a given code. Carefully analyze the code using CWE (Common Weakness Enumeration) descriptions step by step.

Example 1: Vulnerable Code
#define MAX_DIM 100
/* board dimensions */

int m, n, error;
board_square_t *board;
printf("Please specify the board height: \n");
error = scanf("%d", &m);
if (EOF == error) {
    die("No integer passed: Die evil hacker!\n");
}
printf("Please specify the board width: \n");
error = scanf("%d", &n);
if (EOF == error) {
    die("No integer passed: Die evil hacker!\n");
}
if (m > MAX_DIM || n > MAX_DIM) {
    die("Value too large: Die evil hacker!\n");
}
board = (board_square_t*) malloc(m * n * sizeof(board_square_t));

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "board = (board_square_t*) malloc(m * n * sizeof(board_square_t));",
  "reason": "The program does not validate negative inputs for 'm' and 'n'. An attacker could input large negative values, leading to integer overflow (CWE-190) or excessive memory allocation (CWE-789), potentially crashing the system (CWE-400).",
  "cwe": {
    "cwe_id": "CWE-190",
    "name": "Integer Overflow or Wraparound",
    "description": "The software performs a calculation that leads to an integer overflow, potentially causing memory mismanagement or logic errors."
  }
}

Example 2: Vulnerable Code
$birthday = $_GET['birthday'];
$homepage = $_GET['homepage'];
echo "Birthday: $birthday<br>Homepage: <a href=$homepage>click here</a>";

Response:
{
  "is_this_vuln": true,
  "vuln_code_part": "echo \"Birthday: $birthday<br>Homepage: <a href=$homepage>click here</a>\";",
  "reason": "The code directly outputs user-controlled variables without sanitization. An attacker could inject JavaScript (CWE-79) for XSS attacks or manipulate SQL queries (CWE-89) if the values are used in database queries.",
  "cwe": {
    "cwe_id": "CWE-79",
    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "description": "The application does not neutralize user-controlled input before incorporating it into HTML, allowing attackers to execute malicious scripts in the victim's browser."
  }
}

Example 3: Non-vulnerable Code
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public String registerUser(@Valid @RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return "Username already exists";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword())); // Securely hash password
        userRepository.save(user);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public String loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        Optional<User> userOpt = userRepository.findByUsername(loginRequest.getUsername());

        if (userOpt.isPresent() && passwordEncoder.matches(loginRequest.getPassword(), userOpt.get().getPassword())) {
            return "Login successful";
        }
        return "Invalid credentials";
    }
}

Response:
{
  "is_this_vuln": false,
  "vuln_code_part": None,
  "reason": "The code follows secure coding practices: it uses JPA to prevent SQL injection, applies BCrypt for password hashing to avoid plaintext password storage, and enforces input validation (CWE-20) with @Valid. Additionally, it does not expose sensitive information or use hardcoded secrets.",
  "cwe": None
}

Example 4: Non-vulnerable Code
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

Now analyse the code provided and respond accordingly.
code:
"""


def main():
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
  
  logging.info("Loading non-vulnerable code pickle file.")
  with open(f"./dataset/test_pickles/test_non_vuln.pkl", "rb") as f:
    non_vuln = pickle.load(f)
  
  logging.info("Loading vulnerable code pickle file.")
  with open(f"./dataset/test_pickles/test_vuln.pkl", "rb") as f:
    vuln = pickle.load(f)
  
  for prompt_temp, prompt_type in zip([cot_prompt, fs_prompt], ['cot_prompt', 'fs_prompt']):
    for df, code_type in zip([non_vuln, vuln], ['non_vuln_code', 'vuln_code'], ):
      logging.info(f"Classifying {code_type}.")
      results = classify_vuln(df, code_type, prompt_temp)
      
      logging.info(f"Saving results for {code_type}.")
      os.makedirs(f'./result/{prompt_type}', exist_ok=True)
      with open(f"./result/{prompt_type}/{code_type}_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
      
      #logging.info(f"Sleeping for 5 minutes to manage GPU usage.")
      #gpu_utils.sleep_for_minutes(5)
        
    

if __name__ == "__main__":
    main()
