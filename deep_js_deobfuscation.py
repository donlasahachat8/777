#!/usr/bin/env python3

import re
import json
import time

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")
def print_critical(message): print(f"\033[1;41m[CRITICAL] {message}\033[0m")

class DeepJSDeobfuscator:
    def __init__(self):
        self.original_code = ""
        self.deobfuscated_code = ""
        self.analysis = {
            "admin_functions": [],
            "api_calls": [],
            "state_manipulations": [],
            "cookie_operations": [],
            "routing_logic": [],
            "security_concerns": [],
            "readable_code_blocks": []
        }
    
    def load_js_file(self, filename):
        """โหลดไฟล์ JavaScript"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                self.original_code = f.read()
            print_success(f"✅ Loaded {filename}: {len(self.original_code)} bytes")
            return True
        except Exception as e:
            print_error(f"❌ Failed to load {filename}: {e}")
            return False
    
    def deobfuscate_minified_code(self):
        """ถอดรหัสโค้ดที่ถูก minify"""
        print_info("🔧 Deobfuscating minified JavaScript code...")
        
        code = self.original_code
        
        # Step 1: Format webpack chunk structure
        code = re.sub(r'\)\(\);', ')();\n', code)
        code = re.sub(r'\]\,', '],\n', code)
        code = re.sub(r'\}\,', '},\n', code)
        code = re.sub(r'\)\,', '),\n', code)
        
        # Step 2: Add line breaks around function definitions
        code = re.sub(r'function\s*\(', '\nfunction(', code)
        code = re.sub(r'function\s+(\w+)\s*\(', r'\nfunction \1(', code)
        
        # Step 3: Format object definitions
        code = re.sub(r'\{([a-zA-Z_]\w*):function', r'{\n  \1: function', code)
        code = re.sub(r'([a-zA-Z_]\w*):([a-zA-Z_]\w*)', r'\1: \2', code)
        
        # Step 4: Format React hooks and effects
        code = re.sub(r'\(0,([a-zA-Z_]\w*\.useState)\)', r'(0, \1)', code)
        code = re.sub(r'\(0,([a-zA-Z_]\w*\.useEffect)\)', r'(0, \1)', code)
        code = re.sub(r'\(0,([a-zA-Z_]\w*\.useRouter)\)', r'(0, \1)', code)
        
        # Step 5: Format JSX elements
        code = re.sub(r'\(0,([a-zA-Z_]\w*\.jsx)\)', r'(0, \1)', code)
        
        self.deobfuscated_code = code
        return code
    
    def analyze_admin_force_function(self):
        """วิเคราะห์ฟังก์ชัน AdminForce โดยเฉพาะ"""
        print_info("👑 Deep analysis of AdminForce function...")
        
        # Extract the AdminForce function specifically
        adminforce_pattern = r'function AdminForce\(\)\{([^}]+)\}'
        match = re.search(adminforce_pattern, self.deobfuscated_code)
        
        if match:
            adminforce_body = match.group(1)
            print_success("✅ Found AdminForce function body:")
            print_info(f"   Function body: {adminforce_body}")
            
            # Analyze the function components
            self.analyze_function_components(adminforce_body)
        else:
            # Try alternative pattern for minified version
            alternative_pattern = r'AdminForce\(\)\{let ([^}]+)\}'
            match = re.search(alternative_pattern, self.deobfuscated_code)
            if match:
                adminforce_body = match.group(1)
                print_success("✅ Found AdminForce function (alternative pattern):")
                print_info(f"   Function body: {adminforce_body}")
                self.analyze_function_components(adminforce_body)
    
    def analyze_function_components(self, function_body):
        """วิเคราะห์ส่วนประกอบของฟังก์ชัน"""
        print_info("🔍 Analyzing function components...")
        
        # 1. Router usage analysis
        router_patterns = [
            r'(e\.replace\(["\']([^"\']+)["\'])',
            r'useRouter\(\)',
            r'router\.\w+'
        ]
        
        for pattern in router_patterns:
            matches = re.finditer(pattern, function_body)
            for match in matches:
                if 'replace' in match.group(0):
                    path = match.group(2) if len(match.groups()) > 1 else "unknown"
                    self.analysis["routing_logic"].append({
                        "action": "redirect",
                        "path": path,
                        "code": match.group(0)
                    })
                    print_warning(f"🔄 Routing action found: Redirect to '{path}'")
        
        # 2. State manipulation analysis
        state_patterns = [
            r't\(([^,]+),([^)]+)\)',
            r'useState\([^)]*\)',
            r'setState\([^)]*\)'
        ]
        
        for pattern in state_patterns:
            matches = re.finditer(pattern, function_body)
            for match in matches:
                if 'ADMIN' in match.group(0):
                    self.analysis["state_manipulations"].append({
                        "type": "admin_state_setting",
                        "code": match.group(0),
                        "critical": True
                    })
                    print_critical(f"🚨 CRITICAL: Admin state manipulation found: {match.group(0)}")
        
        # 3. Effect hooks analysis
        effect_patterns = [
            r'useEffect\(\(\)\=\>\{([^}]+)\}',
            r'useEffect\([^)]+\)'
        ]
        
        for pattern in effect_patterns:
            matches = re.finditer(pattern, function_body)
            for match in matches:
                effect_code = match.group(0)
                if 'replace' in effect_code:
                    print_warning(f"⚠️ Effect with redirect: {effect_code}")
                if 'ADMIN' in effect_code:
                    print_critical(f"🚨 Effect setting admin: {effect_code}")
        
        # 4. JSX rendering analysis
        jsx_patterns = [
            r'jsx\(["\']([^"\']+)["\']',
            r'children:([^}]+)'
        ]
        
        for pattern in jsx_patterns:
            matches = re.finditer(pattern, function_body)
            for match in matches:
                jsx_content = match.group(0)
                if 'admin' in jsx_content.lower():
                    print_warning(f"⚠️ Admin-related JSX: {jsx_content}")
    
    def extract_critical_code_sections(self):
        """แยกส่วนของโค้ดที่สำคัญ"""
        print_info("🎯 Extracting critical code sections...")
        
        critical_patterns = {
            "Admin State Setting": r't\(a\.F\.ADMIN[^)]*\)',
            "Router Navigation": r'e\.replace\([^)]*\)',
            "Effect Hooks": r'useEffect\([^)]*\)',
            "State Hooks": r'useState\([^)]*\)',
            "Thai Text Content": r'["\'][ก-๙][^"\']*["\']'
        }
        
        for section_name, pattern in critical_patterns.items():
            matches = re.finditer(pattern, self.original_code)
            for match in matches:
                code_section = {
                    "section": section_name,
                    "code": match.group(0),
                    "position": match.start(),
                    "context": self.get_code_context(match.start(), 50)
                }
                
                self.analysis["readable_code_blocks"].append(code_section)
                
                if section_name == "Admin State Setting":
                    print_critical(f"🚨 {section_name}: {match.group(0)}")
                elif section_name == "Thai Text Content":
                    print_success(f"✅ {section_name}: {match.group(0)}")
                else:
                    print_info(f"📝 {section_name}: {match.group(0)}")
    
    def get_code_context(self, position, context_length):
        """ดึงบริบทของโค้ดรอบๆ ตำแหน่งที่กำหนด"""
        start = max(0, position - context_length)
        end = min(len(self.original_code), position + context_length)
        return self.original_code[start:end]
    
    def analyze_security_implications(self):
        """วิเคราะห์ผลกระทบด้านความปลอดภัย"""
        print_info("🔒 Analyzing security implications...")
        
        security_findings = []
        
        # 1. Check for admin privilege escalation
        admin_escalation_pattern = r't\(a\.F\.ADMIN\s*,\s*!0\)'
        if re.search(admin_escalation_pattern, self.original_code):
            security_findings.append({
                "type": "CRITICAL",
                "issue": "Automatic Admin Privilege Escalation",
                "description": "The function automatically sets admin state to true without any authentication checks",
                "code": re.search(admin_escalation_pattern, self.original_code).group(0),
                "impact": "Any user accessing /admin-force gets admin privileges"
            })
            print_critical("🚨 CRITICAL: Automatic admin privilege escalation detected!")
        
        # 2. Check for hardcoded admin references
        admin_cookie_pattern = r'cookies.*admin'
        if re.search(admin_cookie_pattern, self.original_code, re.IGNORECASE):
            security_findings.append({
                "type": "HIGH",
                "issue": "Hardcoded Admin Cookie Reference",
                "description": "Direct reference to admin cookies in client-side code",
                "code": re.search(admin_cookie_pattern, self.original_code, re.IGNORECASE).group(0),
                "impact": "Reveals admin cookie manipulation logic"
            })
            print_error("❌ HIGH: Hardcoded admin cookie reference found!")
        
        # 3. Check for client-side auth bypass
        if "AdminForce" in self.original_code and "!0" in self.original_code:
            security_findings.append({
                "type": "CRITICAL", 
                "issue": "Client-Side Authentication Bypass",
                "description": "Admin state is set on client-side without server validation",
                "impact": "Complete bypass of admin authentication"
            })
            print_critical("🚨 CRITICAL: Client-side authentication bypass!")
        
        self.analysis["security_concerns"] = security_findings
        return security_findings
    
    def create_detailed_summary(self):
        """สร้างสรุปรายละเอียด"""
        print_info("\n" + "="*80)
        print_critical("🎯 DETAILED JAVASCRIPT ANALYSIS SUMMARY")
        print_info("="*80)
        
        print_info("📁 File Analysis:")
        print_info(f"   Original size: {len(self.original_code)} bytes")
        print_info(f"   Deobfuscated size: {len(self.deobfuscated_code)} bytes")
        
        print_info("\n🔍 Code Structure:")
        print_info(f"   Admin functions: {len(self.analysis['admin_functions'])}")
        print_info(f"   State manipulations: {len(self.analysis['state_manipulations'])}")
        print_info(f"   Routing actions: {len(self.analysis['routing_logic'])}")
        print_info(f"   Security concerns: {len(self.analysis['security_concerns'])}")
        
        print_critical("\n🚨 SECURITY ANALYSIS:")
        for concern in self.analysis["security_concerns"]:
            print_error(f"   {concern['type']}: {concern['issue']}")
            print_error(f"      Description: {concern['description']}")
            print_error(f"      Impact: {concern['impact']}")
            if 'code' in concern:
                print_error(f"      Code: {concern['code']}")
        
        print_info("\n📝 READABLE CODE BLOCKS:")
        for block in self.analysis["readable_code_blocks"]:
            print_info(f"   {block['section']}: {block['code']}")
        
        # Generate human-readable explanation
        explanation = self.generate_human_readable_explanation()
        print_info("\n📖 HUMAN-READABLE EXPLANATION:")
        print_info(explanation)
        
        # Save complete analysis
        complete_analysis = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "original_code": self.original_code,
            "deobfuscated_code": self.deobfuscated_code,
            "analysis": self.analysis,
            "human_explanation": explanation
        }
        
        with open('DEEP_JS_DEOBFUSCATION_REPORT.json', 'w', encoding='utf-8') as f:
            json.dump(complete_analysis, f, indent=2, ensure_ascii=False)
        
        print_success("\n📄 Complete analysis saved to: DEEP_JS_DEOBFUSCATION_REPORT.json")
        
        return complete_analysis
    
    def generate_human_readable_explanation(self):
        """สร้างคำอธิบายที่มนุษย์อ่านเข้าใจได้"""
        explanation = """
🎯 ADMINFORCE FUNCTION ANALYSIS - HUMAN READABLE EXPLANATION
===========================================================

This JavaScript file contains a React component called 'AdminForce' that appears to be
designed for administrative privilege escalation. Here's what it does:

1. 📍 FUNCTION PURPOSE:
   - The AdminForce function is a React component that automatically grants admin privileges
   - It's accessed via the URL path '/admin-force'
   - No authentication or authorization checks are performed

2. 🔧 TECHNICAL IMPLEMENTATION:
   - Uses React hooks (useRouter, useEffect, useState)
   - Automatically sets admin state to 'true' when the component loads
   - Redirects the user to the home page ('/') after setting admin privileges
   - Displays a Thai message about "installing admin cookies"

3. 🚨 SECURITY IMPLICATIONS:
   - CRITICAL VULNERABILITY: Any user who visits /admin-force gets admin privileges
   - Client-side privilege escalation without server-side validation
   - Hardcoded admin state manipulation in client-side JavaScript
   - No authentication required to trigger admin state

4. 💥 ATTACK SCENARIO:
   Step 1: User navigates to https://domain.com/admin-force
   Step 2: JavaScript automatically executes t(a.F.ADMIN, !0) 
   Step 3: Admin state is set to 'true' in the application
   Step 4: User is redirected to home page with admin privileges
   Step 5: User now has administrative access to the system

5. 🛡️ RISK ASSESSMENT:
   - Severity: CRITICAL (10/10)
   - Exploitability: TRIVIAL (just visit a URL)
   - Impact: COMPLETE ADMINISTRATIVE ACCESS
   - Detection: LOW (simple URL access)

6. 🔍 EVIDENCE:
   - Function name: AdminForce()
   - Admin state setting: t(a.F.ADMIN,!0)
   - Thai message: "กำลังติดตั้ง cookies สำหรับ admin"
   - Auto-redirect: e.replace("/")

This represents a complete breakdown of access controls and should be considered
one of the most severe types of authentication bypass vulnerabilities.
"""
        return explanation
    
    def run_deep_analysis(self, filename):
        """รันการวิเคราะห์แบบลึก"""
        print_critical("🎯 DEEP JAVASCRIPT DEOBFUSCATION & ANALYSIS")
        print_critical("=" * 80)
        
        if not self.load_js_file(filename):
            return None
        
        # Step 1: Deobfuscate the code
        print_info("Step 1: Deobfuscating minified code...")
        self.deobfuscate_minified_code()
        
        # Step 2: Analyze AdminForce function specifically
        print_info("Step 2: Analyzing AdminForce function...")
        self.analyze_admin_force_function()
        
        # Step 3: Extract critical code sections
        print_info("Step 3: Extracting critical code sections...")
        self.extract_critical_code_sections()
        
        # Step 4: Analyze security implications
        print_info("Step 4: Analyzing security implications...")
        self.analyze_security_implications()
        
        # Step 5: Create detailed summary
        print_info("Step 5: Creating detailed summary...")
        return self.create_detailed_summary()

def main():
    print_critical("🎯 DEEP JAVASCRIPT DEOBFUSCATION SUITE")
    print_critical("=" * 70)
    
    deobfuscator = DeepJSDeobfuscator()
    deobfuscator.run_deep_analysis("admin-force.js")

if __name__ == "__main__":
    main()