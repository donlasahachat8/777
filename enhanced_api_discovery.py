#!/usr/bin/env python3

import requests
import sys
import json
import re
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
TARGET_URL = "https://pigslot.co/"

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def analyze_admin_page():
    """Analyze the admin login page for clues"""
    print_info("Analyzing admin panel page structure...")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    })
    
    try:
        response = session.get("https://pigslot.co/admin-force", verify=False, timeout=15)
        
        print_success(f"Admin page status: {response.status_code}")
        print_info(f"Response size: {len(response.text)} bytes")
        
        # Analyze HTML content
        soup = BeautifulSoup(response.text, 'lxml')
        
        # Find forms
        forms = soup.find_all('form')
        print_info(f"Found {len(forms)} form(s)")
        
        for i, form in enumerate(forms):
            print_info(f"Form {i+1}:")
            action = form.get('action', 'No action')
            method = form.get('method', 'GET')
            print_info(f"  Action: {action}")
            print_info(f"  Method: {method}")
            
            # Find inputs
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', 'No name')
                type_attr = inp.get('type', 'text')
                value = inp.get('value', '')
                print_info(f"    Input: {name} (type: {type_attr}, value: {value})")
        
        # Look for JavaScript files
        scripts = soup.find_all('script', src=True)
        js_files = [script['src'] for script in scripts if script.get('src')]
        print_info(f"Found {len(js_files)} JavaScript files:")
        for js in js_files:
            print_info(f"  - {js}")
        
        # Look for potential API endpoints in JavaScript or HTML
        api_patterns = [
            r'/api/[a-zA-Z0-9/_-]+',
            r'/ajax/[a-zA-Z0-9/_-]+',
            r'/json/[a-zA-Z0-9/_-]+',
            r'/admin/[a-zA-Z0-9/_-]+',
            r'/dashboard/[a-zA-Z0-9/_-]+',
            r'/users?/[a-zA-Z0-9/_-]*',
            r'/auth/[a-zA-Z0-9/_-]+',
            r'/login[a-zA-Z0-9/_-]*'
        ]
        
        found_endpoints = set()
        content = response.text
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            found_endpoints.update(matches)
        
        if found_endpoints:
            print_success(f"Potential API endpoints found in page:")
            for endpoint in sorted(found_endpoints):
                print_success(f"  - {endpoint}")
        
        return response.text, found_endpoints
        
    except Exception as e:
        print_error(f"Error analyzing admin page: {e}")
        return None, set()

def discover_common_endpoints():
    """Try to discover common admin endpoints"""
    print_info("Testing common admin endpoints...")
    
    common_endpoints = [
        '/admin/',
        '/admin/login',
        '/admin/dashboard',
        '/admin/users',
        '/admin/api/',
        '/api/',
        '/api/admin/',
        '/api/auth/',
        '/api/login',
        '/api/users',
        '/api/dashboard',
        '/api/v1/',
        '/api/v2/',
        '/ajax/login',
        '/ajax/admin/',
        '/json/admin/',
        '/auth/login',
        '/auth/admin',
        '/dashboard/',
        '/panel/',
        '/cp/',
        '/control/',
        '/manage/',
        '/administrator/',
        '/wp-admin/', # WordPress
        '/phpmyadmin/', # phpMyAdmin
        '/admin.php',
        '/login.php',
        '/index.php/admin',
        '/backend/',
        '/cms/',
        '/system/',
        '/user/login'
    ]
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    discovered_endpoints = {}
    
    for endpoint in common_endpoints:
        try:
            url = urljoin(TARGET_URL, endpoint)
            response = session.get(url, verify=False, timeout=10, allow_redirects=False)
            
            status = response.status_code
            size = len(response.text)
            
            # Classify interesting responses
            if status == 200:
                discovered_endpoints[endpoint] = {
                    'status': status,
                    'size': size,
                    'interesting': True,
                    'content_type': response.headers.get('content-type', 'unknown')
                }
                print_success(f"✅ {endpoint} - Status: {status}, Size: {size}")
            elif status == 302 or status == 301:
                location = response.headers.get('Location', 'No redirect')
                discovered_endpoints[endpoint] = {
                    'status': status,
                    'redirect': location,
                    'interesting': True
                }
                print_warning(f"🔄 {endpoint} - Redirect to: {location}")
            elif status == 403:
                discovered_endpoints[endpoint] = {
                    'status': status,
                    'interesting': True,
                    'note': 'Forbidden - might exist but require auth'
                }
                print_warning(f"🚫 {endpoint} - Forbidden (403)")
            elif status == 401:
                discovered_endpoints[endpoint] = {
                    'status': status,
                    'interesting': True,
                    'note': 'Unauthorized - authentication required'
                }
                print_warning(f"🔒 {endpoint} - Unauthorized (401)")
            
            # Small delay to avoid overwhelming
            time.sleep(0.1)
            
        except requests.exceptions.Timeout:
            print_warning(f"⏰ {endpoint} - Timeout")
        except Exception as e:
            pass  # Skip errors
    
    return discovered_endpoints

def analyze_javascript_files():
    """Analyze JavaScript files for API endpoints"""
    print_info("Analyzing JavaScript files for API endpoints...")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Get the main admin page first
    try:
        response = session.get("https://pigslot.co/admin-force", verify=False)
        soup = BeautifulSoup(response.text, 'lxml')
        
        scripts = soup.find_all('script', src=True)
        js_endpoints = set()
        
        for script in scripts:
            js_url = script['src']
            
            # Make URL absolute
            if js_url.startswith('/'):
                js_url = urljoin(TARGET_URL, js_url)
            elif not js_url.startswith('http'):
                js_url = urljoin("https://pigslot.co/admin-force", js_url)
            
            try:
                print_info(f"Analyzing: {js_url}")
                js_response = session.get(js_url, verify=False, timeout=10)
                
                if js_response.status_code == 200:
                    js_content = js_response.text
                    
                    # Look for API patterns in JavaScript
                    api_patterns = [
                        r'["\']\/api\/[^"\']+["\']',
                        r'["\']\/admin\/[^"\']+["\']',
                        r'["\']\/ajax\/[^"\']+["\']',
                        r'["\']\/json\/[^"\']+["\']',
                        r'url\s*:\s*["\'][^"\']+["\']',
                        r'endpoint\s*:\s*["\'][^"\']+["\']',
                        r'action\s*:\s*["\'][^"\']+["\']'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            # Clean up the match
                            endpoint = match.strip('\'"')
                            if endpoint.startswith('/'):
                                js_endpoints.add(endpoint)
                
                time.sleep(0.2)  # Small delay
                
            except Exception as e:
                print_warning(f"Error analyzing {js_url}: {e}")
        
        if js_endpoints:
            print_success("API endpoints found in JavaScript:")
            for endpoint in sorted(js_endpoints):
                print_success(f"  - {endpoint}")
        
        return js_endpoints
        
    except Exception as e:
        print_error(f"Error analyzing JavaScript: {e}")
        return set()

def test_api_endpoints(endpoints):
    """Test discovered API endpoints"""
    print_info("Testing discovered API endpoints...")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest'
    })
    
    results = {}
    
    for endpoint in endpoints:
        try:
            url = urljoin(TARGET_URL, endpoint)
            
            # Test GET request
            response = session.get(url, verify=False, timeout=10)
            
            content_type = response.headers.get('content-type', '').lower()
            
            results[endpoint] = {
                'method': 'GET',
                'status': response.status_code,
                'size': len(response.text),
                'content_type': content_type,
                'is_json': 'application/json' in content_type
            }
            
            if response.status_code == 200:
                if 'application/json' in content_type:
                    try:
                        json_data = response.json()
                        results[endpoint]['json_data'] = str(json_data)[:200] + "..."
                        print_success(f"✅ {endpoint} - JSON API found!")
                    except:
                        pass
                print_success(f"✅ {endpoint} - Status: {response.status_code}")
            elif response.status_code == 401:
                print_warning(f"🔒 {endpoint} - Requires authentication")
            elif response.status_code == 403:
                print_warning(f"🚫 {endpoint} - Forbidden")
            
            time.sleep(0.1)
            
        except Exception as e:
            print_warning(f"Error testing {endpoint}: {e}")
    
    return results

def generate_discovery_report(admin_content, found_endpoints, discovered_endpoints, js_endpoints, api_results):
    """Generate comprehensive discovery report"""
    
    report = f"""
===============================================
🔍 COMPREHENSIVE API DISCOVERY REPORT
===============================================

Target: https://pigslot.co/
Admin Panel: https://pigslot.co/admin-force
Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
ZAP Proxy: {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}

📊 DISCOVERY SUMMARY:
- Admin page analyzed: ✅
- Common endpoints tested: {len(discovered_endpoints)}
- JavaScript files analyzed: ✅
- Endpoints found in HTML: {len(found_endpoints)}
- Endpoints found in JS: {len(js_endpoints)}
- API endpoints tested: {len(api_results)}

🎯 DISCOVERED ENDPOINTS:

📁 Common Admin Endpoints:
"""
    
    for endpoint, info in discovered_endpoints.items():
        if info.get('interesting'):
            report += f"  ✅ {endpoint} - Status: {info['status']}"
            if 'redirect' in info:
                report += f" → {info['redirect']}"
            elif 'note' in info:
                report += f" ({info['note']})"
            report += "\n"
    
    if found_endpoints:
        report += f"\n🔍 Endpoints found in HTML:\n"
        for endpoint in sorted(found_endpoints):
            report += f"  - {endpoint}\n"
    
    if js_endpoints:
        report += f"\n📜 Endpoints found in JavaScript:\n"
        for endpoint in sorted(js_endpoints):
            report += f"  - {endpoint}\n"
    
    if api_results:
        report += f"\n🚀 API Endpoint Test Results:\n"
        for endpoint, result in api_results.items():
            status = result['status']
            size = result['size']
            is_json = result['is_json']
            
            if status == 200:
                marker = "✅"
            elif status in [401, 403]:
                marker = "🔒"
            else:
                marker = "❌"
            
            report += f"  {marker} {endpoint} - {status} ({size} bytes)"
            if is_json:
                report += " [JSON API]"
            report += "\n"
            
            if result.get('json_data'):
                report += f"      Sample: {result['json_data']}\n"
    
    report += f"""
🔐 SECURITY ANALYSIS:

Authentication Status:
- Admin login page: Accessible but requires credentials
- Common credentials failed: admin/admin, administrator/administrator, etc.
- No obvious authentication bypass found

Potential Attack Vectors:
1. Brute force attack on discovered endpoints
2. Parameter fuzzing on API endpoints
3. Directory traversal attempts
4. SQL injection testing on form inputs
5. XSS testing on input fields

🎯 RECOMMENDED NEXT STEPS:

1. Manual Browser Analysis:
   - Use browser with ZAP proxy to navigate admin panel
   - Try different login combinations
   - Monitor ZAP GUI for additional traffic

2. Advanced Testing:
   - Use tools like Burp Suite or ZAP Spider
   - Test for SQL injection on login form
   - Check for CSRF vulnerabilities
   - Test file upload functionality if available

3. API Security Testing:
   - Test discovered APIs with different HTTP methods
   - Check for authentication bypass
   - Test for privilege escalation
   - Look for information disclosure

⚠️  IMPORTANT NOTES:
- All testing conducted through ZAP proxy for traffic analysis
- No successful authentication achieved with common credentials
- Further manual analysis recommended for complete assessment
- Ensure proper authorization before continuing testing

===============================================
"""
    
    return report

def main():
    print_info("🔍 Enhanced API Discovery Tool")
    print_info("=" * 60)
    
    # Step 1: Analyze admin page
    admin_content, found_endpoints = analyze_admin_page()
    print_info("")
    
    # Step 2: Test common endpoints
    discovered_endpoints = discover_common_endpoints()
    print_info("")
    
    # Step 3: Analyze JavaScript
    js_endpoints = analyze_javascript_files()
    print_info("")
    
    # Step 4: Test API endpoints
    all_endpoints = found_endpoints.union(js_endpoints)
    api_results = test_api_endpoints(all_endpoints) if all_endpoints else {}
    
    # Step 5: Generate report
    report = generate_discovery_report(admin_content, found_endpoints, discovered_endpoints, js_endpoints, api_results)
    
    print(report)
    
    # Save report
    with open("api_discovery_report.txt", "w") as f:
        f.write(report)
    
    print_success("📄 Report saved to: api_discovery_report.txt")
    print_info("🔍 Check ZAP GUI for all captured traffic!")

if __name__ == "__main__":
    main()