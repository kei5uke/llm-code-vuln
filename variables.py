SYSTEM_PROMPT = "You are a highly skilled code analysis assistant specialized in identifying security vulnerabilities in software code."

ZERO_PROMPT = """Analyze the code and determine if it contains any vulnerabilities.
Choose one of the following CWE categories:
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-352: Cross-Site Request Forgery (CSRF)
- None: No vulnerabilities found

Code:
{}

Answer in JSON format:
{{
  "reasoning": "Detailed explanation of why the code is safe or vulnerable.",
  "cwe_id": "None" or "CWE-XX"
}} 
Your JSON response:"""

COT_PROMPT = """Analyze the code and determine if it contains any vulnerabilities step by step.
1. Examine overall the structure of the code to understand its purpose and functionality.
2. Assess user input handling & data flow. Determine how inputs are received and processed (e.g., user input, file input, API request). Track data flow to check if input validation/sanitization is missing or insufficient.
3. Analyze the code to check if it contains any vulnerabilities.
- If a vulnerability is identified, proceed to steps 4–7.
- If no vulnerabilities are found, the output the following JSON format:
{{
  "reasoning": "Detailed explanation of why the code is safe.",
  "cwe_id": None
}} 

4. Identify which part of the code could cause vulnerabilty. 
5. Explain why the identified area might be vulnerable, providing a detailed explanation referencing CWE descriptions.
6. Based on the analysis, identify the CWE category id.
7. Respond with the following JSON format.
{{
  "reason": "Detailed explanation of why the code is vulnerable.",
  "cwe_id": "CWE-XX",
}}

Choose one of the following CWE categories:
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-352: Cross-Site Request Forgery (CSRF)
- None: No vulnerabilities found

Code:
{}

Your JSON response:"""

FS_PROMPT = """Analyze the code and determine if it contains any vulnerabilities.
Sample 1: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
```
$userName = $_POST["user"];
$command = 'ls -l /home/' . $userName;
system($command);
```
Sample 1 Output:
{{
  "reason": "The $userName variable is not checked for malicious input. An attacker could set the $userName variable to an arbitrary OS command such as: ;rm -rf /",
  "cwe_id": "CWE-74"
}}

Sample 2: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
```
$servername = "localhost";
$username = "username";
$password = "password";
$dbname = "myDB";
$conn = new mysqli($servername, $username, $password, $dbname);
$sql = "SELECT * FROM Users WHERE id = " . $_GET['id'];
$result = $conn->query($sql);
```
Sample 2 Output:
{{
  "reason": "The code does not properly validate or sanitize the input from the user. An attacker could manipulate the 'id' parameter to execute arbitrary SQL commands.",
  "cwe_id": "CWE-89"
}}

Sample 3: CWE-434: Unrestricted Upload of File with Dangerous Type
```
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
if (isset($_POST["submit"])) {{
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if($check !== false) {{
        echo "File is an image - " . $check["mime"] . ".";
        $uploadOk = 1;
    }} else {{
        echo "File is not an image.";
        $uploadOk = 0;
    }}
}}
if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {{
    echo "The file ". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). " has been uploaded.";
}} else {{
    echo "Sorry, there was an error uploading your file.";
}}
```
Sample 3 Output:
{{
  "reason": "The code does not properly validate the file type before uploading. An attacker could upload a malicious file that could be executed on the server.",
  "cwe_id": "CWE-434"
}}
Sample 4: CWE-352: Cross-Site Request Forgery (CSRF)
```
<form action="http://example.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker_account">
  <input type="submit" value="Transfer">
</form>
```
Sample 4 Output:
{{
  "reason": "The form does not include a CSRF token. An attacker could trick a user into submitting the form, causing an unwanted transfer of funds.",
  "cwe_id": "CWE-352"
}}
Sample 5: CWE-20: Improper Input Validation
```
public static final double price = 20.00;
int quantity = currentUser.getAttribute("quantity");
double total = price * quantity;
chargeUser(total);
```
Sample 5 Output:
{{
  "reason": "The code does not validate the input quantity, which can be manipulated by an attacker to perform a business logic attack. This can lead to undercharging or overcharging the user.",
  "cwe_id": "CWE-20"
}}

Sample 6: Non-vulnerable code
```
package main
import (
  "fmt"
  "net/http"
)
func handler(w http.ResponseWriter, r *http.Request) {{
  r.ParseForm()
  fmt.Fprintf(w, "Hello, %s!", r.FormValue("name"))
}}
func main() {{
  http.HandleFunc("/", handler)
  http.ListenAndServe(":8080", nil)
}}
```
Sample 6 Output:
{{
  "reason": "The code properly handles user input and does not contain any vulnerabilities.",
  "cwe_id": None
}}

List of CWE categories:
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-352: Cross-Site Request Forgery (CSRF)
- None: No vulnerabilities found

Code:
{}
Your JSON response:"""

# MODELS = ['llama3.1:8b', 'codellama:13b']
# MODELS = ['phi4:14b']
# MODELS = ['hf.co/Kei5uke/Phi4_FT_func_ep3:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_file:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_func_ver2:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_func_explain:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_file_explain:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_func_explain_ep1:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_trained_with_func_ep1:Q8_0']
# MODELS = ['phi4:14b', 'hf.co/Kei5uke/Phi4_FT_func_ep3:latest', 'hf.co/Kei5uke/Phi4_trained_with_func_explain:latest']
# MODELS = ['hf.co/Kei5uke/Phi4_file_explain:Q8_0']
# MODELS = ['hf.co/Kei5uke/Phi4_file_explain_v2:Q8_0']
MODELS = ['hf.co/Kei5uke/Phi4_func_explain_v2:Q8_0']

TIMEOUT = 180  # 3 minutes
SAVE_INTERVAL = 10  # Save progress every 10%
