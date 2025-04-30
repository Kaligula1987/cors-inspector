# CORS Inspector

A Python script to inspect and test Cross-Origin Resource Sharing (CORS) headers for security vulnerabilities. The tool sends HTTP and OPTIONS requests to a target server and analyzes the server's response to check for common misconfigurations.

## Features
- Tests CORS headers for security vulnerabilities like wildcard origin with credentials.
- Identifies insecure configurations that may expose sensitive data.
- Analyzes the CORS headers from the main request and preflight OPTIONS request.
- Provides a summary report and recommendations for secure CORS setup.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/cors-inspector.git
Navigate to the project folder:

bash
Kopieren
Bearbeiten
cd cors-inspector
Create and activate a virtual environment (optional but recommended):

On Windows:

bash
Kopieren
Bearbeiten
python -m venv venv
.\venv\Scripts\activate
On macOS/Linux:

bash
Kopieren
Bearbeiten
python3 -m venv venv
source venv/bin/activate
Install the required dependencies using pip:

bash
Kopieren
Bearbeiten
pip install -r requirements.txt
Usage
Run the script and paste the raw HTTP request: After installation, you can run the script using:

bash
Kopieren
Bearbeiten
python3 cors_inspector.py
Provide the raw HTTP request: The script will prompt you to paste a raw HTTP request (e.g., from Burp Suite or any other tool). Copy the raw HTTP request into the terminal, then press Ctrl+D (on macOS/Linux) or Ctrl+Z (on Windows) to signal the end of input.

Review the analysis and recommendations: After processing the raw request, the script will analyze the CORS headers and provide a summary of potential vulnerabilities, along with suggestions for improving the security configuration of the target server.

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
