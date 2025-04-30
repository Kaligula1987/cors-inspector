# CORS Inspector

A Python script to inspect and test Cross-Origin Resource Sharing (CORS) headers for security vulnerabilities. The tool sends HTTP and OPTIONS requests to a target server and analyzes the server's response to check for common misconfigurations.

## Features
- Tests CORS headers for security vulnerabilities like wildcard origin with credentials.
- Identifies insecure configurations that may expose sensitive data.
- Analyzes the CORS headers from the main request and preflight OPTIONS request.
- Provides a summary report and recommendations for secure CORS setup.

## Installation
-----------------------------------------------------------------------------------------------------------------------------
1. **Clone the repository:**

   git clone https://github.com/your-username/cors-inspector.git


2.Navigate to the project folder

3. 
python -m venv venv


.\venv\Scripts\activate

5.
python3 -m venv venv


source venv/bin/activate

7.
pip install -r requirements.txt

#go to main tool folder again if your not#

8.
python3 cors_inspector.py


-----------------------------------------------------------------------------------------------------------------------------

Example:
Here is an example of what the script output might look like:

csharp
Kopieren
Bearbeiten
📥 Paste raw HTTP request from Burp Suite, then press Ctrl+D (or Ctrl+Z on Windows):

Raw Request Split into Lines:
['GET /api/data HTTP/1.1', 'Host: example.com', 'Origin: http://evil.com', 'User-Agent: cors-inspector', 'Accept: */*']

Parsed Headers:
{'Host': 'example.com', 'Origin': 'http://evil.com', 'User-Agent': 'cors-inspector', 'Accept': '*/*'}

[+] Sending GET with Origin to http://example.com/api/data
[+] Sending OPTIONS (preflight)...
...

======== 🛡️ CORS INSPECTION SUMMARY ========
🎯 Target URL: http://example.com/api/data
🌍 Origin used: http://evil.com
🍪 Cookies Detected: NO

📥 Main Request Analysis:
  - 🔴 Reflects Origin → vulnerable (could lead to data leakage)

📤 OPTIONS (Preflight) Analysis:
  - 🟠 Wildcard origin → less secure, potentially exposes sensitive data

💡 Recommendations:
  - The site may be vulnerable to CORS misconfigurations. Further testing and mitigation are advised.

✅ Inspection Complete.

Have fun its free!!!
https://buymeacoffee.com/lukassimun
