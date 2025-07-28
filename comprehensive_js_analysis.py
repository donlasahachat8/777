#!/usr/bin/env python3

import re
import json
import time
import base64
import urllib.parse

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")
def print_critical(message): print(f"\033[1;41m[CRITICAL] {message}\033[0m")

class ComprehensiveJSAnalyzer:
    def __init__(self):
        self.js_content = ""
        self.analysis_results = {
            "file_info": {},
            "security_findings": [],
            "admin_functions": [],
            "api_endpoints": [],
            "credentials": [],
            "vulnerabilities": [],
            "sensitive_data": [],
            "code_patterns": [],
            "deobfuscated_parts": []
        }
        
    def load_js_file(self, filename):
        """โหลดไฟล์ JavaScript"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.js_content = f.read()
            
            self.analysis_results["file_info"] = {
                "filename": filename,
                "size": len(self.js_content),
                "lines": len(self.js_content.split('\n')),
                "analysis_date": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            print_success(f"✅ Loaded JavaScript file: {filename}")
            print_info(f"   Size: {len(self.js_content)} bytes")
            return True
            
        except Exception as e:
            print_error(f"❌ Failed to load file {filename}: {e}")
            return False
    
    def deobfuscate_and_beautify(self):
        """ลองถอดรหัสและปรับปรุงการอ่านของโค้ด"""
        print_info("🔧 Attempting to deobfuscate and beautify JavaScript...")
        
        # Replace common minified patterns
        content = self.js_content
        
        # Replace escaped quotes and strings
        try:
            content = content.replace('\\"', '"')
            content = content.replace("\\'", "'")
        except:
            pass
        
        # Try to find and decode any base64 strings
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                if len(decoded) > 3 and decoded.isprintable():
                    self.analysis_results["deobfuscated_parts"].append({
                        "type": "base64_decoded",
                        "original": match[:50] + "...",
                        "decoded": decoded
                    })
                    print_success(f"✅ Base64 decoded: {decoded}")
            except:
                continue
        
        # Try to find URL-encoded strings
        url_encoded_pattern = r'%[0-9A-Fa-f]{2}'
        if re.search(url_encoded_pattern, content):
            try:
                decoded_url = urllib.parse.unquote(content)
                if decoded_url != content:
                    self.analysis_results["deobfuscated_parts"].append({
                        "type": "url_decoded",
                        "original": content[:100] + "...",
                        "decoded": decoded_url[:500] + "..."
                    })
                    print_success("✅ URL decoding applied")
                    content = decoded_url
            except:
                pass
        
        # Format the code better for analysis
        formatted_content = content
        
        # Add line breaks after common JavaScript patterns
        patterns_to_break = [
            r'(\}\)\(\);)',
            r'(\}\,function\()',
            r'(\}\]\,)',
            r'(\}\)\,)'
        ]
        
        for pattern in patterns_to_break:
            formatted_content = re.sub(pattern, r'\1\n', formatted_content)
        
        self.formatted_content = formatted_content
        return formatted_content
    
    def analyze_admin_functionality(self):
        """วิเคราะห์ฟังก์ชันที่เกี่ยวข้องกับ admin"""
        print_info("👑 Analyzing admin functionality...")
        
        admin_patterns = [
            r'function\s+(\w*[Aa]dmin\w*)\s*\(',
            r'(\w*[Aa]dmin\w*)\s*:\s*function',
            r'(\w*[Aa]dmin\w*)\s*=\s*function',
            r'function\s+(\w*[Ff]orce\w*)\s*\(',
            r'\.(\w*[Aa]dmin\w*)\s*\(',
            r'["\'](\w*[Aa]dmin\w*)["\']',
            r'[Aa]dmin[Ff]orce',
            r'[Ss]etAdmin',
            r'[Ii]sAdmin',
            r'[Aa]dminState',
            r'[Aa]dminMode',
            r'[Aa]dminPanel'
        ]
        
        for pattern in admin_patterns:
            matches = re.finditer(pattern, self.js_content, re.IGNORECASE)
            for match in matches:
                admin_func = match.group(1) if match.groups() else match.group(0)
                if admin_func not in self.analysis_results["admin_functions"]:
                    self.analysis_results["admin_functions"].append(admin_func)
                    print_success(f"✅ Admin function found: {admin_func}")
    
    def analyze_api_endpoints(self):
        """วิเคราะห์ API endpoints"""
        print_info("🌐 Analyzing API endpoints...")
        
        api_patterns = [
            r'["\'][/]api[/][^"\']*["\']',
            r'["\']https?://[^"\']*api[^"\']*["\']',
            r'["\'][/]admin[^"\']*["\']',
            r'["\'][/]user[^"\']*["\']',
            r'["\'][/]auth[^"\']*["\']',
            r'["\'][/]login[^"\']*["\']',
            r'["\'][/]wallet[^"\']*["\']',
            r'["\'][/]balance[^"\']*["\']',
            r'["\'][/]referral[^"\']*["\']',
            r'["\'][/]vip[^"\']*["\']',
            r'["\'][/]loyalty[^"\']*["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, self.js_content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(0).strip('"\'')
                if endpoint not in self.analysis_results["api_endpoints"]:
                    self.analysis_results["api_endpoints"].append(endpoint)
                    print_success(f"✅ API endpoint found: {endpoint}")
    
    def analyze_credentials_and_keys(self):
        """วิเคราะห์ credentials และ keys"""
        print_info("🔐 Analyzing credentials and API keys...")
        
        credential_patterns = [
            r'["\']([Aa]pi[Kk]ey|[Aa]ccessToken|[Ss]ecretKey)["\']:\s*["\']([^"\']+)["\']',
            r'["\']([Pp]assword|[Pp]wd|[Pp]ass)["\']:\s*["\']([^"\']+)["\']',
            r'["\']([Uu]sername|[Uu]ser|[Ll]ogin)["\']:\s*["\']([^"\']+)["\']',
            r'["\']([Tt]oken|[Aa]uth|[Bb]earer)["\']:\s*["\']([^"\']+)["\']',
            r'["\']([Kk]ey|[Ss]ecret)["\']:\s*["\']([A-Za-z0-9+/=]{20,})["\']',
            r'Bearer\s+([A-Za-z0-9+/=]{20,})',
            r'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+',  # JWT tokens
        ]
        
        for pattern in credential_patterns:
            matches = re.finditer(pattern, self.js_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    key_type = match.group(1)
                    key_value = match.group(2)
                else:
                    key_type = "Token"
                    key_value = match.group(1) if match.groups() else match.group(0)
                
                credential_info = {
                    "type": key_type,
                    "value": key_value[:50] + "..." if len(key_value) > 50 else key_value,
                    "full_match": match.group(0)
                }
                
                self.analysis_results["credentials"].append(credential_info)
                print_critical(f"🚨 Credential found: {key_type} = {key_value[:20]}...")
    
    def analyze_security_vulnerabilities(self):
        """วิเคราะห์ช่องโหว่ความปลอดภัย"""
        print_info("🔍 Analyzing security vulnerabilities...")
        
        vulnerability_patterns = [
            {
                "name": "Eval Usage",
                "pattern": r'eval\s*\(',
                "severity": "HIGH",
                "description": "Use of eval() can lead to code injection"
            },
            {
                "name": "Document.write Usage", 
                "pattern": r'document\.write\s*\(',
                "severity": "MEDIUM",
                "description": "document.write can lead to XSS"
            },
            {
                "name": "innerHTML Assignment",
                "pattern": r'\.innerHTML\s*=\s*[^;]+[+]',
                "severity": "MEDIUM", 
                "description": "Dynamic innerHTML can lead to XSS"
            },
            {
                "name": "setTimeout with String",
                "pattern": r'setTimeout\s*\(\s*["\'][^"\']*["\']',
                "severity": "MEDIUM",
                "description": "setTimeout with string can lead to code injection"
            },
            {
                "name": "Admin Privilege Escalation",
                "pattern": r't\([a-zA-Z\.]+\.ADMIN\s*,\s*!0\)',
                "severity": "CRITICAL",
                "description": "Direct admin privilege setting without validation"
            },
            {
                "name": "Hardcoded Admin Cookie",
                "pattern": r'cookies?\s*.*admin',
                "severity": "HIGH",
                "description": "Hardcoded admin cookie manipulation"
            }
        ]
        
        for vuln in vulnerability_patterns:
            matches = re.finditer(vuln["pattern"], self.js_content, re.IGNORECASE)
            for match in matches:
                vulnerability_info = {
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "match": match.group(0),
                    "position": match.start()
                }
                
                self.analysis_results["vulnerabilities"].append(vulnerability_info)
                
                if vuln["severity"] == "CRITICAL":
                    print_critical(f"🚨 CRITICAL: {vuln['name']} - {match.group(0)}")
                elif vuln["severity"] == "HIGH":
                    print_error(f"❌ HIGH: {vuln['name']} - {match.group(0)}")
                else:
                    print_warning(f"⚠️ {vuln['severity']}: {vuln['name']}")
    
    def analyze_sensitive_data(self):
        """วิเคราะห์ข้อมูลที่อาจเป็นความลับ"""
        print_info("🔒 Analyzing sensitive data...")
        
        sensitive_patterns = [
            {
                "name": "Thai Text Messages",
                "pattern": r'["\'][ก-๙\s]+["\']',
                "description": "Thai language strings that might contain sensitive info"
            },
            {
                "name": "Error Messages", 
                "pattern": r'["\'][^"\']*[Ee]rror[^"\']*["\']',
                "description": "Error messages that might reveal system info"
            },
            {
                "name": "Debug Information",
                "pattern": r'["\'][^"\']*[Dd]ebug[^"\']*["\']',
                "description": "Debug information that should not be in production"
            },
            {
                "name": "Internal Paths",
                "pattern": r'["\'][^"\']*[/\\][^"\']*["\']',
                "description": "Internal file paths or URLs"
            },
            {
                "name": "Version Information",
                "pattern": r'["\']v?\d+\.\d+\.\d+["\']',
                "description": "Version numbers that might reveal system versions"
            }
        ]
        
        for pattern_info in sensitive_patterns:
            matches = re.finditer(pattern_info["pattern"], self.js_content)
            unique_matches = set()
            
            for match in matches:
                match_text = match.group(0)
                if len(match_text) > 3 and match_text not in unique_matches:
                    unique_matches.add(match_text)
                    
                    sensitive_info = {
                        "type": pattern_info["name"],
                        "value": match_text,
                        "description": pattern_info["description"]
                    }
                    
                    self.analysis_results["sensitive_data"].append(sensitive_info)
                    
                    if pattern_info["name"] == "Thai Text Messages":
                        print_success(f"✅ Thai text found: {match_text}")
    
    def analyze_code_patterns(self):
        """วิเคราะห์รูปแบบของโค้ด"""
        print_info("📊 Analyzing code patterns...")
        
        patterns = {
            "React Hooks": r'use[A-Z][a-zA-Z]*',
            "State Management": r'useState|useEffect|useContext',
            "Router Usage": r'useRouter|router\.',
            "API Calls": r'fetch\(|axios\.|\.get\(|\.post\(',
            "Cookie Manipulation": r'cookie|Cookie',
            "Local Storage": r'localStorage|sessionStorage',
            "Admin Checks": r'admin|Admin|ADMIN',
            "Authentication": r'auth|Auth|token|Token',
            "Error Handling": r'try\s*\{|catch\s*\(',
            "Webpack Chunks": r'webpackChunk|chunk'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = len(re.findall(pattern, self.js_content, re.IGNORECASE))
            if matches > 0:
                self.analysis_results["code_patterns"].append({
                    "pattern": pattern_name,
                    "count": matches
                })
                print_info(f"📈 {pattern_name}: {matches} occurrences")
    
    def extract_readable_strings(self):
        """แยกข้อความที่อ่านได้"""
        print_info("📝 Extracting readable strings...")
        
        # Extract strings between quotes
        string_patterns = [
            r'"([^"]{3,})"',
            r"'([^']{3,})'",
        ]
        
        extracted_strings = set()
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, self.js_content)
            for match in matches:
                string_content = match.group(1)
                if len(string_content) >= 3:
                    extracted_strings.add(string_content)
        
        # Filter for interesting strings
        interesting_strings = []
        keywords = ['admin', 'user', 'api', 'token', 'key', 'password', 'auth', 'login', 
                   'error', 'debug', 'config', 'secret', 'ก-๙']
        
        for string in extracted_strings:
            if any(keyword in string.lower() for keyword in keywords) or re.search(r'[ก-๙]', string):
                interesting_strings.append(string)
        
        return interesting_strings
    
    def generate_comprehensive_report(self):
        """สร้างรายงานครบถ้วน"""
        print_info("\n" + "="*80)
        print_critical("🎯 COMPREHENSIVE JAVASCRIPT ANALYSIS REPORT")
        print_info("="*80)
        
        # File information
        file_info = self.analysis_results["file_info"]
        print_info(f"📁 File: {file_info.get('filename', 'Unknown')}")
        print_info(f"📊 Size: {file_info.get('size', 0)} bytes")
        print_info(f"📄 Lines: {file_info.get('lines', 0)}")
        
        # Security summary
        vuln_count = len(self.analysis_results["vulnerabilities"])
        cred_count = len(self.analysis_results["credentials"])
        admin_count = len(self.analysis_results["admin_functions"])
        api_count = len(self.analysis_results["api_endpoints"])
        
        print_info(f"\n🔍 SECURITY SUMMARY:")
        print_info(f"   Vulnerabilities: {vuln_count}")
        print_info(f"   Credentials: {cred_count}")
        print_info(f"   Admin Functions: {admin_count}")
        print_info(f"   API Endpoints: {api_count}")
        
        # Detailed findings
        if self.analysis_results["vulnerabilities"]:
            print_critical("\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.analysis_results["vulnerabilities"]:
                print_error(f"   {vuln['severity']}: {vuln['name']}")
                print_error(f"      Description: {vuln['description']}")
                print_error(f"      Code: {vuln['match']}")
        
        if self.analysis_results["credentials"]:
            print_critical("\n🔐 CREDENTIALS FOUND:")
            for cred in self.analysis_results["credentials"]:
                print_error(f"   {cred['type']}: {cred['value']}")
        
        if self.analysis_results["admin_functions"]:
            print_warning("\n👑 ADMIN FUNCTIONS:")
            for func in self.analysis_results["admin_functions"]:
                print_warning(f"   {func}")
        
        if self.analysis_results["api_endpoints"]:
            print_info("\n🌐 API ENDPOINTS:")
            for endpoint in self.analysis_results["api_endpoints"]:
                print_info(f"   {endpoint}")
        
        # Extract interesting strings
        interesting_strings = self.extract_readable_strings()
        if interesting_strings:
            print_info("\n📝 INTERESTING STRINGS:")
            for string in list(interesting_strings)[:10]:  # Show first 10
                print_info(f"   \"{string}\"")
        
        # Save detailed report
        report_data = {
            "analysis_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "file_info": self.analysis_results["file_info"],
            "security_summary": {
                "vulnerabilities_count": vuln_count,
                "credentials_count": cred_count,
                "admin_functions_count": admin_count,
                "api_endpoints_count": api_count
            },
            "detailed_findings": self.analysis_results,
            "interesting_strings": list(interesting_strings)[:20]
        }
        
        with open('COMPREHENSIVE_JS_ANALYSIS_REPORT.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print_success(f"\n📄 Comprehensive report saved to: COMPREHENSIVE_JS_ANALYSIS_REPORT.json")
        
        # Risk assessment
        risk_level = "LOW"
        if vuln_count > 0:
            critical_vulns = [v for v in self.analysis_results["vulnerabilities"] if v["severity"] == "CRITICAL"]
            high_vulns = [v for v in self.analysis_results["vulnerabilities"] if v["severity"] == "HIGH"]
            
            if critical_vulns:
                risk_level = "CRITICAL"
            elif high_vulns:
                risk_level = "HIGH"
            elif vuln_count > 0:
                risk_level = "MEDIUM"
        
        print_critical(f"\n🎯 OVERALL RISK LEVEL: {risk_level}")
        
        return report_data
    
    def run_comprehensive_analysis(self, filename):
        """รันการวิเคราะห์ครบถ้วน"""
        print_critical("🎯 COMPREHENSIVE JAVASCRIPT SECURITY ANALYSIS")
        print_critical("=" * 80)
        
        if not self.load_js_file(filename):
            return None
        
        # Step 1: Deobfuscate and beautify
        print_info("\nStep 1: Deobfuscation and beautification...")
        self.deobfuscate_and_beautify()
        
        # Step 2: Analyze admin functionality
        print_info("\nStep 2: Admin functionality analysis...")
        self.analyze_admin_functionality()
        
        # Step 3: Analyze API endpoints
        print_info("\nStep 3: API endpoint analysis...")
        self.analyze_api_endpoints()
        
        # Step 4: Analyze credentials
        print_info("\nStep 4: Credential analysis...")
        self.analyze_credentials_and_keys()
        
        # Step 5: Analyze vulnerabilities
        print_info("\nStep 5: Security vulnerability analysis...")
        self.analyze_security_vulnerabilities()
        
        # Step 6: Analyze sensitive data
        print_info("\nStep 6: Sensitive data analysis...")
        self.analyze_sensitive_data()
        
        # Step 7: Analyze code patterns
        print_info("\nStep 7: Code pattern analysis...")
        self.analyze_code_patterns()
        
        # Step 8: Generate comprehensive report
        print_info("\nStep 8: Generating comprehensive report...")
        return self.generate_comprehensive_report()

def main():
    print_critical("🎯 COMPREHENSIVE JAVASCRIPT ANALYSIS SUITE")
    print_critical("=" * 70)
    
    analyzer = ComprehensiveJSAnalyzer()
    
    # Analyze the admin-force.js file
    print_info("Analyzing admin-force.js file...")
    analyzer.run_comprehensive_analysis("admin-force.js")

if __name__ == "__main__":
    main()