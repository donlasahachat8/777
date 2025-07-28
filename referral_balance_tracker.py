#!/usr/bin/env python3

import requests
import json
import time
import sys

# Configuration
API_DOMAIN = "https://jklmn23456.com"
FRONTEND_DOMAIN = "https://pigslot.co"

# User Information
REFERRER_PHONE = "0960422161"
REFERRER_PASSWORD = "181242"
REFERRER_CODE = "PS663888386"

# Known JWT Token (from previous session)
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

class ReferralBalanceTracker:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.headers.update({
            'Authorization': f'bearer {JWT_TOKEN}',
            'Username': REFERRER_PHONE,
            'Password': REFERRER_PASSWORD,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json'
        })
        
    def comprehensive_balance_check(self):
        """ตรวจสอบยอดเงินครอบคลุมทุก endpoint ที่เป็นไปได้"""
        print_info("💰 Comprehensive Balance Check")
        print_info("=" * 50)
        
        balance_endpoints = [
            # Wallet endpoints
            f"{API_DOMAIN}/api/v1/wallet/balance",
            f"{API_DOMAIN}/api/v1/wallet/info",
            f"{API_DOMAIN}/api/v1/wallet/status",
            f"{API_DOMAIN}/api/v1/wallet/details",
            f"{API_DOMAIN}/api/v1/wallet/summary",
            
            # User balance endpoints
            f"{API_DOMAIN}/api/v1/user/balance",
            f"{API_DOMAIN}/api/v1/user/wallet",
            f"{API_DOMAIN}/api/v1/user/financial",
            f"{API_DOMAIN}/api/v1/user/credit",
            f"{API_DOMAIN}/api/v1/user/money",
            
            # Account endpoints
            f"{API_DOMAIN}/api/v1/account/balance",
            f"{API_DOMAIN}/api/v1/account/wallet",
            f"{API_DOMAIN}/api/v1/account/financial",
            
            # Loyalty/Customer specific endpoints
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/balance",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/wallet",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/financial",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/credit",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/vip/status",
            
            # Generic endpoints
            f"{API_DOMAIN}/api/v1/balance",
            f"{API_DOMAIN}/api/balance",
            f"{API_DOMAIN}/balance",
            
            # Profile endpoints (may contain balance)
            f"{API_DOMAIN}/api/v1/profile",
            f"{API_DOMAIN}/api/v1/user/profile",
            f"{API_DOMAIN}/api/v1/me",
        ]
        
        balance_data = {}
        
        for endpoint in balance_endpoints:
            try:
                response = self.session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ Balance endpoint found: {endpoint}")
                            print_info(f"   Response: {str(data)[:400]}...")
                            balance_data[endpoint] = data
                            
                            # Try to extract specific balance values
                            if 'data' in data:
                                self.extract_balance_info(endpoint, data['data'])
                        
                    except Exception as e:
                        if len(response.text) > 10:
                            print_warning(f"⚠️ Non-JSON response from {endpoint}: {response.text[:100]}...")
                        
            except Exception as e:
                continue
        
        return balance_data
    
    def extract_balance_info(self, endpoint, data):
        """แยกข้อมูลยอดเงินจากข้อมูลที่ได้รับ"""
        balance_fields = [
            'balance', 'wallet_balance', 'total_balance', 'current_balance',
            'available_balance', 'credit_balance', 'main_balance',
            'amount', 'total_amount', 'available_amount',
            'money', 'credit', 'funds', 'cash'
        ]
        
        for field in balance_fields:
            if field in data:
                value = data[field]
                print_critical(f"💰 {field}: {value} (from {endpoint.split('/')[-1]})")
        
        # Check for nested balance data
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and any(bf in value for bf in balance_fields):
                    print_info(f"📊 Balance section '{key}': {value}")
    
    def comprehensive_referral_check(self):
        """ตรวจสอบข้อมูลระบบแนะนำเพื่อนครอบคลุม"""
        print_info("👥 Comprehensive Referral System Check")
        print_info("=" * 50)
        
        referral_endpoints = [
            # Main referral endpoints
            f"{API_DOMAIN}/api/v1/referral/stats",
            f"{API_DOMAIN}/api/v1/referral/statistics",
            f"{API_DOMAIN}/api/v1/referral/info",
            f"{API_DOMAIN}/api/v1/referral/details",
            f"{API_DOMAIN}/api/v1/referral/summary",
            f"{API_DOMAIN}/api/v1/referral/status",
            f"{API_DOMAIN}/api/v1/referral/balance",
            f"{API_DOMAIN}/api/v1/referral/rewards",
            f"{API_DOMAIN}/api/v1/referral/earnings",
            f"{API_DOMAIN}/api/v1/referral/history",
            f"{API_DOMAIN}/api/v1/referral/list",
            f"{API_DOMAIN}/api/v1/referral/members",
            f"{API_DOMAIN}/api/v1/referral/count",
            
            # Invite endpoints
            f"{API_DOMAIN}/api/v1/invite/stats",
            f"{API_DOMAIN}/api/v1/invite/info",
            f"{API_DOMAIN}/api/v1/invite/rewards",
            f"{API_DOMAIN}/api/v1/invite/history",
            f"{API_DOMAIN}/api/v1/invite/list",
            f"{API_DOMAIN}/api/v1/invite/count",
            
            # User referral endpoints
            f"{API_DOMAIN}/api/v1/user/referrals",
            f"{API_DOMAIN}/api/v1/user/invites",
            f"{API_DOMAIN}/api/v1/user/referral/stats",
            f"{API_DOMAIN}/api/v1/user/invite/stats",
            
            # Loyalty specific referral endpoints
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/referrals",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/invites",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/referral/stats",
            f"{API_DOMAIN}/api/v1/loyalty/{REFERRER_CODE}/referral/rewards",
            
            # Generic endpoints
            f"{API_DOMAIN}/api/v1/stats/referral",
            f"{API_DOMAIN}/api/referral",
            f"{API_DOMAIN}/api/invite",
        ]
        
        referral_data = {}
        
        for endpoint in referral_endpoints:
            try:
                response = self.session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ Referral endpoint found: {endpoint}")
                            print_info(f"   Response: {str(data)[:300]}...")
                            referral_data[endpoint] = data
                            
                            # Extract referral statistics
                            if 'data' in data:
                                self.extract_referral_info(endpoint, data['data'])
                        
                    except Exception as e:
                        if len(response.text) > 10:
                            print_warning(f"⚠️ Non-JSON response from {endpoint}")
                        
            except Exception as e:
                continue
        
        return referral_data
    
    def extract_referral_info(self, endpoint, data):
        """แยกข้อมูลแนะนำเพื่อนจากข้อมูลที่ได้รับ"""
        referral_fields = [
            'total_referrals', 'referral_count', 'invite_count',
            'verified_referrals', 'pending_referrals',
            'total_rewards', 'referral_rewards', 'invite_rewards',
            'earned_amount', 'total_earned', 'commission',
            'referral_bonus', 'invite_bonus'
        ]
        
        for field in referral_fields:
            if field in data:
                value = data[field]
                print_critical(f"👥 {field}: {value} (from {endpoint.split('/')[-1]})")
        
        # Check for arrays of referrals
        if isinstance(data, list):
            print_critical(f"📋 Referral list found: {len(data)} items")
            for i, item in enumerate(data[:3]):  # Show first 3 items
                print_info(f"   Item {i+1}: {str(item)[:100]}...")
        
        # Check for nested referral data
        if isinstance(data, dict):
            for key, value in data.items():
                if 'referral' in key.lower() or 'invite' in key.lower():
                    print_info(f"📊 Referral section '{key}': {value}")
    
    def check_referral_conditions(self):
        """ตรวจสอบเงื่อนไขการได้รับรางวัลแนะนำเพื่อน"""
        print_info("📋 Checking Referral Reward Conditions")
        print_info("=" * 50)
        
        condition_endpoints = [
            f"{API_DOMAIN}/api/v1/referral/conditions",
            f"{API_DOMAIN}/api/v1/referral/requirements",
            f"{API_DOMAIN}/api/v1/referral/rules",
            f"{API_DOMAIN}/api/v1/referral/policy",
            f"{API_DOMAIN}/api/v1/invite/conditions",
            f"{API_DOMAIN}/api/v1/invite/requirements",
            f"{API_DOMAIN}/api/v1/system/referral/config",
            f"{API_DOMAIN}/api/v1/config/referral",
            f"{API_DOMAIN}/api/v1/settings/referral"
        ]
        
        for endpoint in condition_endpoints:
            try:
                response = self.session.get(endpoint, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ Condition endpoint found: {endpoint}")
                            print_info(f"   Response: {data}")
                    except:
                        if len(response.text) > 10:
                            print_info(f"📄 Text response: {response.text[:200]}...")
                        
            except:
                continue
    
    def test_referral_reward_triggers(self):
        """ทดสอบการ trigger รางวัลแนะนำเพื่อน"""
        print_info("🎯 Testing Referral Reward Triggers")
        print_info("=" * 50)
        
        trigger_endpoints = [
            f"{API_DOMAIN}/api/v1/referral/claim",
            f"{API_DOMAIN}/api/v1/referral/trigger",
            f"{API_DOMAIN}/api/v1/referral/activate",
            f"{API_DOMAIN}/api/v1/referral/process",
            f"{API_DOMAIN}/api/v1/referral/reward/claim",
            f"{API_DOMAIN}/api/v1/invite/claim",
            f"{API_DOMAIN}/api/v1/invite/trigger",
            f"{API_DOMAIN}/api/v1/rewards/claim",
            f"{API_DOMAIN}/api/v1/bonus/claim"
        ]
        
        trigger_payloads = [
            {},
            {"action": "claim"},
            {"type": "referral"},
            {"claim": True},
            {"process": "referral_rewards"},
            {"trigger": "referral_bonus"}
        ]
        
        for endpoint in trigger_endpoints:
            for payload in trigger_payloads:
                try:
                    response = self.session.post(endpoint, json=payload, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data.get('status') == 'SUCCESS':
                                print_critical(f"🚨 REWARD TRIGGER SUCCESSFUL!")
                                print_critical(f"   Endpoint: {endpoint}")
                                print_critical(f"   Payload: {payload}")
                                print_critical(f"   Response: {data}")
                        except:
                            if 'success' in response.text.lower():
                                print_critical(f"🚨 TRIGGER MAY BE SUCCESSFUL!")
                                print_critical(f"   Endpoint: {endpoint}")
                                
                except:
                    continue
    
    def comprehensive_api_discovery(self):
        """ค้นหา API endpoints ที่เกี่ยวข้องกับเงินและรางวัล"""
        print_info("🔍 Comprehensive API Discovery")
        print_info("=" * 50)
        
        # Test common API patterns
        api_patterns = [
            "/api/v1/wallet",
            "/api/v1/balance",
            "/api/v1/money",
            "/api/v1/credit",
            "/api/v1/referral",
            "/api/v1/invite",
            "/api/v1/reward",
            "/api/v1/bonus",
            "/api/v1/earning",
            "/api/v1/commission",
            "/api/v1/loyalty",
            "/api/v1/vip",
            "/api/v1/promotion",
            "/api/v1/campaign"
        ]
        
        discovered_apis = []
        
        for pattern in api_patterns:
            try:
                response = self.session.get(f"{API_DOMAIN}{pattern}", timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status') == 'SUCCESS':
                            print_success(f"✅ API pattern found: {pattern}")
                            discovered_apis.append(pattern)
                    except:
                        if len(response.text) > 10:
                            print_success(f"✅ API pattern found (non-JSON): {pattern}")
                            discovered_apis.append(pattern)
                            
            except:
                continue
        
        return discovered_apis
    
    def run_comprehensive_analysis(self):
        """รันการวิเคราะห์ครบถ้วน"""
        print_critical("🎯 COMPREHENSIVE REFERRAL BALANCE ANALYSIS")
        print_critical("=" * 80)
        
        print_info(f"User: {REFERRER_PHONE}")
        print_info(f"Customer Code: {REFERRER_CODE}")
        print_info(f"JWT Token: {JWT_TOKEN[:50]}...")
        print_info("")
        
        # Step 1: Check all balance endpoints
        print_info("STEP 1: Comprehensive balance check...")
        balance_data = self.comprehensive_balance_check()
        
        # Step 2: Check all referral endpoints  
        print_info("\nSTEP 2: Comprehensive referral system check...")
        referral_data = self.comprehensive_referral_check()
        
        # Step 3: Check referral conditions
        print_info("\nSTEP 3: Checking referral conditions...")
        self.check_referral_conditions()
        
        # Step 4: Test reward triggers
        print_info("\nSTEP 4: Testing reward triggers...")
        self.test_referral_reward_triggers()
        
        # Step 5: API discovery
        print_info("\nSTEP 5: API discovery...")
        discovered_apis = self.comprehensive_api_discovery()
        
        # Generate summary
        self.generate_analysis_summary(balance_data, referral_data, discovered_apis)
    
    def generate_analysis_summary(self, balance_data, referral_data, discovered_apis):
        """สร้างสรุปผลการวิเคราะห์"""
        print_info("\n" + "="*80)
        print_critical("🎯 ANALYSIS SUMMARY")
        print_info("="*80)
        
        print_info(f"📊 Balance endpoints found: {len(balance_data)}")
        print_info(f"👥 Referral endpoints found: {len(referral_data)}")
        print_info(f"🔍 API patterns discovered: {len(discovered_apis)}")
        
        # Check if we found any useful data
        has_balance_info = any('balance' in str(data).lower() for data in balance_data.values())
        has_referral_info = any('referral' in str(data).lower() for data in referral_data.values())
        
        if has_balance_info:
            print_success("✅ Balance information accessible")
        else:
            print_warning("⚠️ No balance information found")
        
        if has_referral_info:
            print_success("✅ Referral information accessible")
        else:
            print_warning("⚠️ No referral information found")
        
        # Save detailed report
        report = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "user": REFERRER_PHONE,
            "customer_code": REFERRER_CODE,
            "balance_endpoints": len(balance_data),
            "referral_endpoints": len(referral_data),
            "discovered_apis": discovered_apis,
            "balance_data": balance_data,
            "referral_data": referral_data
        }
        
        with open('REFERRAL_BALANCE_ANALYSIS.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print_success(f"\n📄 Detailed analysis saved to: REFERRAL_BALANCE_ANALYSIS.json")
        
        # Final recommendation
        if has_balance_info and has_referral_info:
            print_critical("\n🎯 RECOMMENDATION: System accessible - monitor for balance changes")
        elif has_balance_info or has_referral_info:
            print_warning("\n🎯 RECOMMENDATION: Partial access - continue investigation")
        else:
            print_info("\n🎯 RECOMMENDATION: Limited access - may require additional authentication")

def main():
    print_critical("🎯 REFERRAL BALANCE TRACKING SYSTEM")
    print_critical("=" * 70)
    
    tracker = ReferralBalanceTracker()
    tracker.run_comprehensive_analysis()

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()