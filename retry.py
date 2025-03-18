import ollama
from typing import Union, Dict, Any
from pydantic import BaseModel
import json
import logging
import time
import tiktoken
import pickle
import gc
import multiprocessing

# Define Pydantic models
class ClassifyTemplate(BaseModel):
    cwe_id: str
    name: str
    description: str

class ResponseTemplate(BaseModel):
    is_this_vuln: bool
    vuln_code_part: Union[str, None]
    reason: Union[str, None]
    cwe: Union[ClassifyTemplate, None]

# Define prompts
prompt = """
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

# Load datasets
with open('./dataset/test_pickles_bak/test_non_vuln.pkl', 'rb') as file:
    non_vuln = pickle.load(file)
with open('./dataset/test_pickles_bak/test_vuln.pkl', 'rb') as file:
    vuln = pickle.load(file)

with open('./result/FT_fs_non_vuln_code_results.json') as file:
    non_vuln_result = json.load(file)
with open('./result/FT_fs_vuln_code_results.json') as file:
    vuln_result = json.load(file)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("progress.log"),  # Log to a file
        logging.StreamHandler()  # Log to the console
    ]
)
logger = logging.getLogger(__name__)

models = ['hf.co/Kei5uke/llama3:latest', 'hf.co/Kei5uke/codellama:latest', 'hf.co/Kei5uke/phi4:latest', 'hf.co/Kei5uke/deepseek:latest']
start_time = time.time()

# Define timeout duration (in seconds)
TIMEOUT = 180  # 3 minutes

def call_ollama(model: str, prompt_temp: str, code: str, token_count: int) -> Dict[str, Any]:
    """
    Calls the Ollama API with a timeout feature using multiprocessing.

    Args:
        model (str): The model to use for the API call.
        prompt_temp (str): The system prompt template.
        code (str): The code to analyze.
        token_count (int): The token count for the API call.

    Returns:
        Dict[str, Any]: The API response or an error message if the call times out or fails.
    """
    queue = multiprocessing.Queue()

    def api_call(q: multiprocessing.Queue) -> None:
        """
        Internal function to make the Ollama API call and put the result in the queue.

        Args:
            q (multiprocessing.Queue): The queue to store the API response or error.
        """
        try:
            response = ollama.chat(
                model=model,
                messages=[
                    {"role": "system", "content": prompt_temp},
                    {"role": "user", "content": code},
                ],
                options={"temperature": 0, "num_ctx": token_count},
                format=ResponseTemplate.model_json_schema(),
            )
            q.put(response)
        except Exception as e:
            q.put({"error": str(e)})

    # Start the API call in a separate process
    process = multiprocessing.Process(target=api_call, args=(queue,))
    process.start()
    process.join(timeout=TIMEOUT)  # Wait for the process to complete or timeout

    # Handle timeout or process completion
    if process.is_alive():
        process.terminate()  # Terminate the process if it's still running
        process.join()
        return {"error": f"Ollama API call timed out after {TIMEOUT} seconds"}

    # Retrieve the result from the queue
    return queue.get() if not queue.empty() else {"error": "No response from API"}

# Function to validate if a string is valid JSON
def is_valid_json(json_str: str) -> bool:
    try:
        json.loads(json_str)
        return True
    except ValueError:
        return False

# Process both DataFrames
for df, result_list, tag in zip([vuln, non_vuln], [vuln_result, non_vuln_result], ['vuln_code', 'non_vuln_code']):
    logger.info(f"Processing DataFrame: {tag}")

    # Iterate over each row in the DataFrame
    for df_index in range(len(df)):
        # Calculate the starting index in the result_list for this df_index
        # Each df_index has len(models) entries in the result list
        start_result_idx = df_index * len(models)

        # Iterate through all models for this df_index
        for model_idx, model in enumerate(models):
            result_idx = start_result_idx + model_idx

            # Ensure result_list has enough entries
            if result_idx >= len(result_list):
                logger.warning(f"Result index {result_idx} out of bounds for {tag}. Skipping.")
                continue

            item = result_list[result_idx]
            if item.get('result') is not None:
                logger.info(f"Skipping {tag} index {result_idx} (df_index={df_index}, model={model}): Already processed.")
                continue

            # Build context
            context = fs_prompt + '\n' + df.iloc[df_index][tag]
            encoding = tiktoken.get_encoding("cl100k_base")
            token_count = len(encoding.encode(context)) + 500

            try:
                logger.info(f"Processing df_index={df_index} ({tag}), model={model} [result_idx={result_idx}]")

                # Call ollama with timeout
                response = call_ollama(model, prompt, df.iloc[df_index][tag], token_count)
                if "error" in response:
                    logger.warning(f"Error for df_index={df_index} ({tag}), model={model}: {response['error']}")
                    item.update({'model': model, 'retry': True, 'result': None})
                    continue

                # Validate JSON
                content = response['message']['content']
                if not is_valid_json(content):
                    logger.warning(f"Invalid JSON for df_index={df_index} ({tag}), model={model}")
                    content = None

                # Update result
                item.update({
                    'model': model,
                    'retry': True,
                    'result': content
                })
                logger.info(f"Successfully processed df_index={df_index} ({tag}), model={model}")

            except Exception as e:
                logger.error(f"Critical error at df_index={df_index} ({tag}), model={model}: {str(e)}")
                item.update({'model': model, 'retry': True, 'result': None})

        # Save after completing all models for this df_index
        with open(f'./{tag}_retry.json', 'w') as f:
            json.dump(result_list, f, indent=4)
        logger.info(f"Saved {tag} results up to df_index={df_index} (models 1-{len(models)})")

        # Pause to release GPU memory
        if time.time() - start_time >= 1200:
            logger.info("Pausing for 3 minutes to release GPU memory...")
            gc.collect()
            time.sleep(180)
            start_time = time.time()
            logger.info("Resuming processing after pause.")
