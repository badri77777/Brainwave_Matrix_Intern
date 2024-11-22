# Brainwave_Matrix_Intern
Phishing Link Scanner
A Python-based tool to detect phishing URLs by analyzing patterns, domain structures, and optionally integrating with threat intelligence services like VirusTotal.

Overview
----------------
Phishing is a major cybersecurity threat where attackers trick users into providing sensitive information by using malicious links. This project provides a simple, user-friendly phishing link scanner that can:

Analyze URLs for common phishing patterns.
Check for suspicious domains.
Optionally integrate with VirusTotal API for advanced detection.
This tool is designed to be lightweight and easy to use, providing users with a quick and efficient way to identify potentially harmful links.

Features
--------------
1) Pattern-Based Detection:
   Flags suspicious links with unusual characters, excessive hyphens, or phishing keywords like login, secure, update, etc.

2) Domain Analysis:
   Checks domains for anomalies such as suspicious subdomains or phishing-related terms.
   
3) Threat Intelligence (Optional):
   Integrates with the VirusTotal API to query real-time URL threat intelligence.
   
4) Command-Line Interface (CLI):
   Allows users to input URLs and get immediate results on their safety.

How It Works
---------------------
1. Pattern Matching:
   Regular expressions (regex) are used to identify suspicious URL structures.

2. Examples:
URLs with @ symbols or excessive hyphens.
URLs using IP addresses instead of domain names.

3. Domain Analysis:
   Parses the URL to extract the domain and flags it if it contains phishing-related terms like login, secure, or update.
   
4. Optional VirusTotal Check:
   If a VirusTotal API key is provided, the scanner queries the API to check if the URL is flagged as malicious by the broader cybersecurity community.
Installation

Prerequisites:
-------------------------
Install Python 3.20.0 on your system.

Install required libraries:
-------------------------------
pip install requests

Clone or Download the project repository:
-----------------------------------------------
git clone https://github.com/badri77777/phishing-link-scanner.git
cd phishing-link-scanner
Usage

Run the Python script:
-------------------------
python phishing_link_scanner.py
You will see a prompt:
Welcome to the Phishing Link Scanner!
Enter a URL to analyze (or type 'exit' to quit):
Enter your VirusTotal API key (or leave blank to skip):
Input the URL you want to analyze:

Example:
------------------
URL: http://secure-login.xyz/update
The tool will analyze the URL and display the result:
Result: Suspicious: Domain contains phishing indicators
To exit, type exit at the URL prompt.

Sample Outputs
-------------------------
Example 1: Suspicious URL
URL: http://secure-login.xyz/update
Result: Suspicious: Domain contains phishing indicators
Example 2: Safe URL
URL: https://google.com
Result: Safe: No suspicious activity detected
Example 3: VirusTotal Integration
If a VirusTotal API key is provided and the URL is flagged as malicious:
URL: http://malicious-site.com
Result: Malicious: Verified by VirusTotal
Project Structure
phishing-link-scanner/

Customizations
-------------------------
1) Add More Patterns: Modify the check_url_patterns() function to include additional phishing patterns.
   
2) Enhance Domain Analysis: Extend the check_domain() function with custom logic to detect more domain anomalies.

3) GUI Interface: Convert the CLI into a graphical interface using Tkinter or a web app with Flask.

Future Enhancements
----------------------------
1) Machine Learning:
   Using a labelled dataset, train a model to classify URLs as safe or malicious.

2) Browser Extension:
   Develop a browser plugin to scan URLs before opening them.

3) Real-Time Email Scanning:
   Integrate the tool with email systems to detect phishing emails.

4) Acknowledgements
   VirusTotal API: This is used to provide URL reputation checks.
   Python Libraries: re, urllib.parse, requests.


