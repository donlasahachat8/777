#!/usr/bin/env python3

import requests
import sys
import json
import re
import urllib3
import base64
import time
from urllib.parse import urljoin, urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
TARGET_URL = "https://pigslot.co/"

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def download_admin_js():
    """Download the admin-force JavaScript file"""
    print_info("🔍 Downloading admin-force JavaScript file...")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
    })
    
    js_url = "https://pigslot.co/_next/static/chunks/pages/admin-force-c06ca2711d7847b2.js"
    
    try:
        response = session.get(js_url, verify=False, timeout=15)
        
        if response.status_code == 200:
            print_success(f"✅ Successfully downloaded JavaScript file")
            print_info(f"File size: {len(response.text)} bytes")
            
            # Save to file for analysis
            with open("admin-force.js", "w", encoding='utf-8') as f:
                f.write(response.text)
            
            return response.text
        else:
            print_error(f"Failed to download JS file. Status: {response.status_code}")
            return None
            
    except Exception as e:
        print_error(f"Error downloading JS file: {e}")
        return None

def extract_credentials(js_content):
    """Extract potential hardcoded credentials"""
    print_info("🔐 Searching for hardcoded credentials...")
    
    credentials = {}
    
    # Common credential patterns
    credential_patterns = [
        # Username/password patterns
        (r'(?i)(?:username|user|login|email)\s*[:=]\s*["\']([^"\']+)["\']', 'username'),
        (r'(?i)(?:password|pass|pwd|secret)\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
        (r'(?i)(?:admin|administrator)\s*[:=]\s*["\']([^"\']+)["\']', 'admin'),
        
        # API keys and tokens
        (r'(?i)(?:api_key|apikey|api-key)\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'(?i)(?:token|access_token|auth_token)\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
        (r'(?i)(?:secret|private_key|private-key)\s*[:=]\s*["\']([^"\']+)["\']', 'secret'),
        
        # Database credentials
        (r'(?i)(?:db_user|database_user|db_username)\s*[:=]\s*["\']([^"\']+)["\']', 'db_user'),
        (r'(?i)(?:db_pass|database_pass|db_password)\s*[:=]\s*["\']([^"\']+)["\']', 'db_pass'),
        
        # Common default credentials
        (r'["\']admin["\'].*["\']admin["\']', 'admin_admin'),
        (r'["\']administrator["\'].*["\']password["\']', 'admin_password'),
        (r'["\']root["\'].*["\']123456["\']', 'root_123456'),
    ]
    
    for pattern, cred_type in credential_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            credentials[cred_type] = matches
            for match in matches:
                print_success(f"🎯 Found {cred_type}: {match}")
    
    # Look for base64 encoded credentials
    base64_patterns = [
        r'(?:btoa|atob)\s*\(\s*["\']([^"\']+)["\']',
        r'["\'][A-Za-z0-9+/]{20,}={0,2}["\']'
    ]
    
    for pattern in base64_patterns:
        matches = re.findall(pattern, js_content)
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                if ':' in decoded or '@' in decoded:
                    credentials['base64_decoded'] = credentials.get('base64_decoded', [])
                    credentials['base64_decoded'].append(f"{match} -> {decoded}")
                    print_success(f"🔓 Base64 decoded: {match} -> {decoded}")
            except:
                pass
    
    return credentials

def extract_api_endpoints(js_content):
    """Extract API endpoints from JavaScript"""
    print_info("🌐 Searching for API endpoints...")
    
    api_endpoints = set()
    
    # API endpoint patterns
    api_patterns = [
        # Standard API patterns
        r'["\']([^"\']*\/api\/[^"\']*)["\']',
        r'["\']([^"\']*\/admin\/[^"\']*)["\']',
        r'["\']([^"\']*\/ajax\/[^"\']*)["\']',
        r'["\']([^"\']*\/json\/[^"\']*)["\']',
        r'["\']([^"\']*\/auth\/[^"\']*)["\']',
        r'["\']([^"\']*\/login[^"\']*)["\']',
        r'["\']([^"\']*\/logout[^"\']*)["\']',
        r'["\']([^"\']*\/dashboard[^"\']*)["\']',
        r'["\']([^"\']*\/users?[^"\']*)["\']',
        r'["\']([^"\']*\/profile[^"\']*)["\']',
        r'["\']([^"\']*\/settings[^"\']*)["\']',
        
        # URL patterns in fetch/axios calls
        r'(?:fetch|axios|request)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:url|endpoint|path)\s*[:=]\s*["\']([^"\']+)["\']',
        
        # Next.js specific patterns
        r'["\']([^"\']*\/_next\/[^"\']*)["\']',
        r'["\']([^"\']*\/trpc\/[^"\']*)["\']',
    ]
    
    for pattern in api_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if match.startswith('/') or match.startswith('http'):
                api_endpoints.add(match)
    
    # Sort and display findings
    sorted_endpoints = sorted(api_endpoints)
    
    if sorted_endpoints:
        print_success(f"🎯 Found {len(sorted_endpoints)} potential API endpoints:")
        for endpoint in sorted_endpoints:
            print_success(f"  - {endpoint}")
    else:
        print_warning("No API endpoints found")
    
    return sorted_endpoints

def extract_authentication_logic(js_content):
    """Analyze authentication and authorization logic"""
    print_info("🔒 Analyzing authentication logic...")
    
    auth_info = {}
    
    # Authentication patterns
    auth_patterns = [
        # Function definitions
        (r'(?:function\s+|const\s+|let\s+|var\s+)(\w*(?:auth|login|verify|check)\w*)', 'auth_functions'),
        (r'(?:function\s+|const\s+|let\s+|var\s+)(\w*(?:admin|role|permission)\w*)', 'admin_functions'),
        
        # Authentication checks
        (r'(?:if\s*\(|return\s+)([^;{}]*(?:auth|login|admin|role|permission)[^;{}]*)', 'auth_checks'),
        
        # Cookie/localStorage patterns
        (r'(?:localStorage|sessionStorage|cookie)\.(?:get|set)Item\s*\(\s*["\']([^"\']+)["\']', 'storage_keys'),
        
        # JWT patterns
        (r'["\'][A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']', 'potential_jwt'),
        
        # Authorization headers
        (r'["\'](?:Authorization|Bearer|Token)["\']', 'auth_headers'),
    ]
    
    for pattern, info_type in auth_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            auth_info[info_type] = matches
            print_success(f"🔍 Found {info_type}:")
            for match in matches[:10]:  # Limit output
                print_info(f"  - {match}")
            if len(matches) > 10:
                print_info(f"  ... and {len(matches) - 10} more")
    
    return auth_info

def analyze_admin_permissions(js_content):
    """Look for admin-specific functionality and permissions"""
    print_info("👑 Searching for admin-specific functionality...")
    
    admin_features = {}
    
    # Admin-specific patterns
    admin_patterns = [
        # Admin role checks
        (r'(?:role|permission|admin|superuser)\s*(?:===|==|!==|!=)\s*["\']([^"\']+)["\']', 'role_checks'),
        
        # Admin routes/paths
        (r'["\']([^"\']*admin[^"\']*)["\']', 'admin_paths'),
        
        # Permission/capability checks
        (r'(?:can|has|check)(?:Permission|Access|Role)\s*\([^)]*["\']([^"\']+)["\']', 'permissions'),
        
        # Admin actions
        (r'(?:delete|remove|ban|suspend|manage)\w*', 'admin_actions'),
    ]
    
    for pattern, feature_type in admin_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            # Remove duplicates and filter
            unique_matches = list(set(matches))
            admin_features[feature_type] = unique_matches
            
            print_success(f"🎯 Found {feature_type}:")
            for match in unique_matches[:10]:
                print_info(f"  - {match}")
            if len(unique_matches) > 10:
                print_info(f"  ... and {len(unique_matches) - 10} more")
    
    return admin_features

def search_for_vulnerabilities(js_content):
    """Look for potential security vulnerabilities in the code"""
    print_info("🚨 Searching for potential vulnerabilities...")
    
    vulnerabilities = {}
    
    # Vulnerability patterns
    vuln_patterns = [
        # Dangerous functions
        (r'(?:eval|setTimeout|setInterval)\s*\([^)]*["\']([^"\']+)["\']', 'code_injection'),
        (r'innerHTML\s*=\s*[^;]+', 'xss_potential'),
        (r'(?:document\.write|document\.writeln)\s*\([^)]*', 'dom_manipulation'),
        
        # Hardcoded secrets in conditions
        (r'(?:if|when|check)\s*\([^)]*["\']([^"\']{8,})["\']', 'hardcoded_values'),
        
        # Insecure storage
        (r'localStorage\.setItem\s*\([^)]*(?:password|token|secret)', 'insecure_storage'),
        
        # Debug/development code
        (r'(?:console\.log|alert|confirm)\s*\([^)]*', 'debug_code'),
    ]
    
    for pattern, vuln_type in vuln_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            vulnerabilities[vuln_type] = matches
            print_warning(f"⚠️ Found {vuln_type}:")
            for match in matches[:5]:
                print_warning(f"  - {match}")
            if len(matches) > 5:
                print_warning(f"  ... and {len(matches) - 5} more")
    
    return vulnerabilities

def test_discovered_endpoints(endpoints):
    """Test discovered API endpoints"""
    print_info("🧪 Testing discovered endpoints...")
    
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest'
    })
    
    results = {}
    
    for endpoint in endpoints[:20]:  # Test first 20 endpoints
        if not endpoint.startswith('/'):
            continue
            
        try:
            url = urljoin(TARGET_URL, endpoint)
            response = session.get(url, verify=False, timeout=10)
            
            results[endpoint] = {
                'status': response.status_code,
                'size': len(response.text),
                'content_type': response.headers.get('content-type', '')
            }
            
            if response.status_code == 200:
                print_success(f"✅ {endpoint} - Status: 200")
                if 'application/json' in response.headers.get('content-type', ''):
                    try:
                        json_data = response.json()
                        results[endpoint]['json'] = json_data
                        print_success(f"    JSON Response: {str(json_data)[:100]}...")
                    except:
                        pass
            elif response.status_code in [401, 403]:
                print_warning(f"🔒 {endpoint} - Status: {response.status_code} (Auth required)")
            elif response.status_code != 404:
                print_info(f"❓ {endpoint} - Status: {response.status_code}")
            
            time.sleep(0.1)
            
        except Exception as e:
            print_warning(f"Error testing {endpoint}: {e}")
    
    return results

def generate_comprehensive_report(js_content, credentials, endpoints, auth_info, admin_features, vulnerabilities, endpoint_results):
    """Generate comprehensive analysis report"""
    
    report = f"""
🔍 JAVASCRIPT SECURITY ANALYSIS REPORT
=====================================

Target: https://pigslot.co/_next/static/chunks/pages/admin-force-c06ca2711d7847b2.js
Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}
File Size: {len(js_content)} bytes

📊 EXECUTIVE SUMMARY:
===================
- Hardcoded Credentials: {len(credentials)}
- API Endpoints Found: {len(endpoints)}
- Auth Functions: {len(auth_info)}
- Admin Features: {len(admin_features)}
- Potential Vulnerabilities: {len(vulnerabilities)}

🔐 DISCOVERED CREDENTIALS:
=========================
"""
    
    if credentials:
        for cred_type, values in credentials.items():
            report += f"\n{cred_type.upper()}:\n"
            for value in values:
                report += f"  - {value}\n"
    else:
        report += "\n❌ No hardcoded credentials found\n"
    
    report += f"\n🌐 API ENDPOINTS DISCOVERED:\n"
    report += "===========================\n"
    
    if endpoints:
        for endpoint in endpoints:
            report += f"  - {endpoint}\n"
            if endpoint in endpoint_results:
                result = endpoint_results[endpoint]
                report += f"    Status: {result['status']} | Size: {result['size']} bytes\n"
                if 'json' in result:
                    report += f"    JSON: {str(result['json'])[:100]}...\n"
    else:
        report += "\n❌ No API endpoints found\n"
    
    report += f"\n🔒 AUTHENTICATION ANALYSIS:\n"
    report += "===========================\n"
    
    if auth_info:
        for auth_type, values in auth_info.items():
            report += f"\n{auth_type.upper()}:\n"
            for value in values[:10]:
                report += f"  - {value}\n"
            if len(values) > 10:
                report += f"  ... and {len(values) - 10} more\n"
    else:
        report += "\n❌ No authentication logic found\n"
    
    report += f"\n👑 ADMIN FUNCTIONALITY:\n"
    report += "======================\n"
    
    if admin_features:
        for feature_type, values in admin_features.items():
            report += f"\n{feature_type.upper()}:\n"
            for value in values[:10]:
                report += f"  - {value}\n"
            if len(values) > 10:
                report += f"  ... and {len(values) - 10} more\n"
    else:
        report += "\n❌ No admin-specific features found\n"
    
    report += f"\n🚨 SECURITY VULNERABILITIES:\n"
    report += "===========================\n"
    
    if vulnerabilities:
        for vuln_type, values in vulnerabilities.items():
            report += f"\n⚠️ {vuln_type.upper()}:\n"
            for value in values[:5]:
                report += f"  - {value}\n"
            if len(values) > 5:
                report += f"  ... and {len(values) - 5} more\n"
    else:
        report += "\n✅ No obvious vulnerabilities found\n"
    
    # Risk assessment
    risk_level = "LOW"
    if credentials or vulnerabilities:
        risk_level = "HIGH"
    elif endpoints or admin_features:
        risk_level = "MEDIUM"
    
    report += f"""

🛡️ RISK ASSESSMENT:
==================
Overall Risk Level: {risk_level}

Recommendations:
1. Review any hardcoded credentials found
2. Test discovered API endpoints for unauthorized access
3. Analyze authentication logic for bypasses
4. Check admin functionality for privilege escalation
5. Fix any security vulnerabilities identified

=====================================
End of Analysis Report
=====================================
"""
    
    return report

def main():
    print_info("🎯 JavaScript Security Analyzer for Admin Panel")
    print_info("=" * 60)
    
    # Step 1: Download JavaScript file
    js_content = download_admin_js()
    if not js_content:
        print_error("Could not download JavaScript file. Exiting.")
        return
    
    print_info("")
    
    # Step 2: Extract credentials
    credentials = extract_credentials(js_content)
    print_info("")
    
    # Step 3: Extract API endpoints
    endpoints = extract_api_endpoints(js_content)
    print_info("")
    
    # Step 4: Analyze authentication logic
    auth_info = extract_authentication_logic(js_content)
    print_info("")
    
    # Step 5: Search for admin functionality
    admin_features = analyze_admin_permissions(js_content)
    print_info("")
    
    # Step 6: Look for vulnerabilities
    vulnerabilities = search_for_vulnerabilities(js_content)
    print_info("")
    
    # Step 7: Test discovered endpoints
    endpoint_results = test_discovered_endpoints(endpoints) if endpoints else {}
    print_info("")
    
    # Step 8: Generate comprehensive report
    report = generate_comprehensive_report(
        js_content, credentials, endpoints, auth_info, 
        admin_features, vulnerabilities, endpoint_results
    )
    
    print(report)
    
    # Save report
    with open("javascript_analysis_report.txt", "w", encoding='utf-8') as f:
        f.write(report)
    
    print_success("📄 Complete analysis saved to: javascript_analysis_report.txt")
    print_success("📄 JavaScript file saved to: admin-force.js")
    
    # Summary
    total_findings = len(credentials) + len(endpoints) + len(vulnerabilities)
    if total_findings > 0:
        print_success(f"🎯 ANALYSIS COMPLETE: {total_findings} security findings discovered!")
    else:
        print_warning("⚠️ Limited findings - file may be minified or obfuscated")

if __name__ == "__main__":
    main()