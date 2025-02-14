import os
import re
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Set API keys (Use environment variables in production)
VIRUSTOTAL_API_KEY = "bc7504cbea5c71c7098ef1d2f2963031941b4bc7770237418c615fc27522dc78"

# Improved Payload Analysis Function
def analyze_payload(payload):
    result = {
        "type": "Unknown",
        "functions": [],
        "mitre_attack": []
    }

    # Detect PowerShell-based payloads
    if re.search(r'(?i)System\.Net\.Sockets\.TCPClient', payload) or re.search(r'(?i)New-Object', payload):
        result["type"] = "PowerShell Reverse Shell"
        result["functions"].append("Command Execution")
        result["mitre_attack"].append("T1059 - Command and Scripting Interpreter")

    if re.search(r'(?i)bash', payload):
        result["type"] = "Bash Reverse Shell"
        result["functions"].append("Command Execution")
        result["mitre_attack"].append("T1059.004 - Unix Shell")

    if re.search(r'(?i)base64', payload):
        result["functions"].append("Obfuscation Detected")
        result["mitre_attack"].append("T1027 - Obfuscated Files or Information")

    if re.search(r'(?i)net user', payload):
        result["functions"].append("Privilege Escalation")
        result["mitre_attack"].append("T1068 - Exploitation for Privilege Escalation")

    if re.search(r'(?i)nc | ncat | netcat', payload):
        result["functions"].append("Network Connectivity - Possible Backdoor")
        result["mitre_attack"].append("T1105 - Ingress Tool Transfer")

    if re.search(r'(?i)mshta', payload):
        result["functions"].append("Malicious Scripting - Possible Remote Execution")
        result["mitre_attack"].append("T1218.005 - Mshta")

    if re.search(r'(?i)cmd.exe', payload):
        result["functions"].append("Command-Line Interface Detected")
        result["mitre_attack"].append("T1059.003 - Windows Command Shell")

    if re.search(r'(?i)wget|curl', payload):
        result["functions"].append("Downloading Files from the Internet")
        result["mitre_attack"].append("T1102 - Web Shell")

    return result

# VirusTotal Lookup
def check_virustotal(payload):
    url = "https://www.virustotal.com/api/v3/files"
    
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key is missing."}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Save payload to a temporary file before sending it
    with open("temp_payload.txt", "w") as temp_file:
        temp_file.write(payload)

    files = {"file": open("temp_payload.txt", "rb")}
    response = requests.post(url, headers=headers, files=files)
    files["file"].close()

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return {"error": "Error retrieving VirusTotal data."}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        payload = request.form.get("payload")
        analysis_result = analyze_payload(payload)
        vt_result = check_virustotal(payload)
        
        return jsonify({
            "analysis": analysis_result,
            "virustotal": vt_result
        })
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
