import re  # Regular expressions library for pattern matching
from urllib.parse import urlparse  # Library to parse URLs into components
import requests  # Library for making HTTP requests (used for VirusTotal API)

# === 1. URL Analysis Functions ===

# Function to check for suspicious patterns in the URL
def check_url_patterns(url):
    """
    Checks the URL for common phishing patterns using regular expressions.
    """
    # List of suspicious patterns to match
    patterns = [
        r'@',  # '@' symbol in the URL
        r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP address instead of domain
        r'([a-z0-9]+-){2,}',  # Excessive hyphens in the domain
        r'(login|account|secure|update|verify|payment|confirm)'  # Common phishing keywords
    ]
    # Check if any pattern matches the URL
    for pattern in patterns:
        if re.search(pattern, url):
            return True  # Suspicious pattern found
    return False  # No suspicious patterns detected

# Function to parse the URL into components
def parse_url(url):
    """
    Parses the URL and extracts its components (scheme, domain, path).
    """
    try:
        parsed = urlparse(url)  # Parse the URL
        scheme = parsed.scheme  # e.g., http, https
        domain = parsed.netloc  # e.g., www.example.com
        path = parsed.path  # Path after the domain
        return scheme, domain, path
    except Exception as e:
        print(f"Error parsing URL: {e}")
        return None, None, None  # Return None if parsing fails

# Function to check the domain for suspicious keywords
def check_domain(domain):
    """
    Flags the domain if it contains phishing-related keywords.
    """
    if not domain:  # Ensure the domain is valid
        return False
    # Keywords commonly used in phishing domains
    suspicious_keywords = ["login", "secure", "update", "verify"]
    for keyword in suspicious_keywords:
        if keyword in domain:
            return True  # Domain is suspicious
    return False  # Domain is safe

# === 2. Threat Intelligence Integration (Optional) ===

# Function to check the URL against VirusTotal API
def check_virustotal(api_key, url):
    """
    Queries the VirusTotal API to determine if the URL is flagged as malicious.
    """
    try:
        # VirusTotal API endpoint for URL scanning
        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}  # API key for authentication
        # Make a POST request to scan the URL
        response = requests.post(vt_url, headers=headers, data={"url": url})
        # If the response is successful, analyze the result
        if response.status_code == 200:
            result = response.json()
            # Check if the URL is flagged as malicious
            if result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                return True  # URL is malicious
        return False  # URL is safe
    except Exception as e:
        print(f"VirusTotal API error: {e}")
        return None  # Return None if the API call fails

# === 3. Main Scanner Logic ===

def phishing_link_scanner(url, api_key=None):
    """
    Main function to analyze a URL for phishing indicators.
    Combines URL analysis and optional VirusTotal scanning.
    """
    # Step 1: Parse the URL
    scheme, domain, path = parse_url(url)
    if not domain:
        return "Invalid URL"  # Return if URL parsing fails

    # Step 2: Check URL patterns for suspicious indicators
    if check_url_patterns(url):
        return "Suspicious: URL contains phishing patterns"

    # Step 3: Check the domain for phishing-related keywords
    if check_domain(domain):
        return "Suspicious: Domain contains phishing indicators"

    # Step 4: Optional - Check the URL against VirusTotal
    if api_key:
        vt_result = check_virustotal(api_key, url)
        if vt_result:
            return "Malicious: Verified by VirusTotal"
        elif vt_result is None:
            return "VirusTotal check failed"

    # If no issues were detected, classify the URL as safe
    return "Safe: No suspicious activity detected"

# === 4. User Interface ===

if __name__ == "__main__":
    print("Welcome to the Phishing Link Scanner!")  # Greeting message
    print("Enter a URL to analyze (or type 'exit' to quit):")
    
    # Prompt user for a VirusTotal API key (optional)
    API_KEY = input("Enter your VirusTotal API key (or leave blank to skip): ").strip() or None

    # Main loop for continuous URL analysis
    while True:
        # Prompt the user to input a URL
        user_input = input("\nURL: ").strip()
        if user_input.lower() == "exit":
            print("Exiting Phishing Link Scanner. Stay safe!")  # Exit message
            break
        
        # Analyze the URL and print the result
        result = phishing_link_scanner(user_input, api_key=API_KEY)
        print(f"Result: {result}")
