from flask import Flask, render_template, request, jsonify
import requests
import re
import tldextract
from bs4 import BeautifulSoup
import json
import os
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)

def check_virustotal(url):
    try:
        # Get API key from environment variable
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not api_key:
            print("Warning: VIRUSTOTAL_API_KEY not found in environment variables")
            return False
            
        # VirusTotal API endpoint
        vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
        
        params = {
            'apikey': api_key,
            'resource': url
        }
        
        headers = {
            'User-Agent': 'PhishDetector/1.0'
        }
        
        response = requests.get(vt_url, params=params, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            # Check if the URL is malicious
            # VirusTotal returns a 'positives' field indicating how many engines detected it as malicious
            return result.get('positives', 0) > 0
        else:
            print(f"VirusTotal API error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error checking VirusTotal: {str(e)}")
        return False

def check_suspicious_patterns(url):
    patterns = {
        'numbers_in_domain': False,
        'excessive_subdomains': False,
        'special_chars': False
    }
    
    # Extract domain
    extracted = tldextract.extract(url)
    domain = extracted.domain
    
    # Check for numbers in domain
    if any(char.isdigit() for char in domain):
        patterns['numbers_in_domain'] = True
    
    # Check for excessive subdomains
    if len(extracted.subdomain.split('.')) > 2:
        patterns['excessive_subdomains'] = True
    
    # Check for special characters (excluding : and / which are valid URL characters)
    special_chars = re.findall(r'[^a-zA-Z0-9.:/-]', url)
    if special_chars:
        patterns['special_chars'] = True
    
    return patterns

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Add http:// if not present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Check VirusTotal
    is_virustotal_blacklisted = check_virustotal(url)
    
    # Check suspicious patterns
    suspicious_patterns = check_suspicious_patterns(url)
    
    # Determine if URL is suspicious
    is_suspicious = is_virustotal_blacklisted or any(suspicious_patterns.values())
    
    return jsonify({
        'url': url,
        'is_suspicious': is_suspicious,
        'virustotal_blacklisted': is_virustotal_blacklisted,
        'suspicious_patterns': suspicious_patterns
    })

if __name__ == '__main__':
    app.run(debug=True) 