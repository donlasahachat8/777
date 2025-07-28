#!/usr/bin/env python3

import requests
import urllib3
import re
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080
ADMIN_ENDPOINT = "https://pigslot.co/admin-force"

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_warning(message): print(f"\033[1;33m[!] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def inspect_admin_force_page():
    """Inspect the admin-force page content in detail"""
    print_info("🔍 INSPECTING ADMIN-FORCE PAGE CONTENT")
    print_info("=" * 60)
    
    session = requests.Session()
    session.proxies = PROXIES
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    try:
        response = session.get(ADMIN_ENDPOINT, timeout=10)
        content = response.text
        
        print_success(f"✅ Response Status: {response.status_code}")
        print_info(f"Content Length: {len(content)} bytes")
        print_info("=" * 60)
        
        # Check for admin-related JavaScript
        print_info("🔍 SEARCHING FOR ADMIN JAVASCRIPT CODE")
        
        # Look for the specific admin function
        if "AdminForce" in content:
            print_success("✅ Found 'AdminForce' function in content!")
        else:
            print_warning("❌ 'AdminForce' function not found")
            
        if "a.F.ADMIN" in content:
            print_success("✅ Found 'a.F.ADMIN' admin state in content!")
        else:
            print_warning("❌ 'a.F.ADMIN' admin state not found")
            
        if "กำลังติดตั้ง cookies สำหรับ admin" in content:
            print_success("✅ Found Thai admin message in content!")
        else:
            print_warning("❌ Thai admin message not found")
            
        # Look for JavaScript chunks
        js_chunks = re.findall(r'/_next/static/chunks/[^"]+\.js', content)
        if js_chunks:
            print_success(f"✅ Found {len(js_chunks)} JavaScript chunks:")
            for chunk in js_chunks:
                print_info(f"   • {chunk}")
        
        # Look for webpack chunks
        webpack_matches = re.findall(r'webpackChunk_N_E.*?push.*?\[\[(.*?)\]', content, re.DOTALL)
        if webpack_matches:
            print_success(f"✅ Found Webpack chunks in content!")
            for match in webpack_matches[:3]:  # Show first 3 matches
                print_info(f"   • Chunk: {match[:100]}...")
        
        # Check for Next.js pages
        nextjs_pages = re.findall(r'__NEXT_P.*?push.*?\["([^"]+)"', content)
        if nextjs_pages:
            print_success(f"✅ Found Next.js pages:")
            for page in nextjs_pages:
                print_info(f"   • {page}")
                if "admin" in page.lower():
                    print_success(f"     🎯 ADMIN PAGE FOUND: {page}")
        
        print_info("=" * 60)
        print_info("🧪 ANALYZING PAGE STRUCTURE")
        
        # Parse HTML structure
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Look for script tags
            scripts = soup.find_all('script')
            print_info(f"Found {len(scripts)} script tags")
            
            # Check for inline JavaScript
            for i, script in enumerate(scripts[:5]):  # Check first 5 scripts
                if script.string and len(script.string) > 100:
                    script_content = script.string[:200]
                    if any(keyword in script_content for keyword in ['admin', 'Admin', 'ADMIN']):
                        print_success(f"✅ Script {i+1} contains admin-related code:")
                        print_info(f"   {script_content}...")
            
            # Look for meta tags that might indicate functionality
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('name') and 'admin' in str(meta.get('content', '')).lower():
                    print_success(f"✅ Admin-related meta tag: {meta}")
            
        except Exception as e:
            print_warning(f"Error parsing HTML: {e}")
        
        print_info("=" * 60)
        print_info("📝 CONTENT SAMPLE (First 500 chars)")
        print_info(content[:500])
        print_info("..." if len(content) > 500 else "")
        
        # Search for key patterns in the content
        patterns_to_check = [
            r'function AdminForce',
            r'a\.F\.ADMIN',
            r'useEffect.*admin',
            r'admin.*cookies',
            r'กำลังติดตั้ง.*admin',
            r'__N_SSP',
            r'webpackChunk_N_E'
        ]
        
        print_info("=" * 60)
        print_info("🔍 PATTERN MATCHING RESULTS")
        
        found_patterns = []
        for pattern in patterns_to_check:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                print_success(f"✅ Pattern '{pattern}': {len(matches)} matches")
                found_patterns.append(pattern)
                # Show first match
                if matches[0]:
                    print_info(f"   First match: {matches[0]}")
            else:
                print_warning(f"❌ Pattern '{pattern}': No matches")
        
        # Final assessment
        print_info("=" * 60)
        print_info("📊 FINAL ASSESSMENT")
        
        if found_patterns:
            print_success(f"✅ Found {len(found_patterns)} matching patterns")
            print_info("The page contains JavaScript code, but it may:")
            print_info("1. Only set client-side state (not server-side privileges)")
            print_info("2. Require additional server-side validation")
            print_info("3. Be a demonstration page without actual admin functionality")
        else:
            print_warning("❌ No admin-related patterns found")
            print_warning("The page may not contain the expected admin functionality")
        
        return {
            'status_code': response.status_code,
            'content_length': len(content),
            'patterns_found': found_patterns,
            'js_chunks': js_chunks,
            'nextjs_pages': nextjs_pages
        }
        
    except Exception as e:
        print_error(f"Error inspecting page: {e}")
        return None

if __name__ == "__main__":
    result = inspect_admin_force_page()
    
    print_info("=" * 60)
    print_info("🎯 CONCLUSION")
    
    if result and result['patterns_found']:
        print_warning("⚠️ POTENTIAL ISSUE DETECTED")
        print_warning("The page contains admin-related JavaScript code,")
        print_warning("but it does NOT grant actual server-side admin privileges.")
        print_warning("")
        print_warning("This appears to be a client-side only demonstration")
        print_warning("that does not bypass server-side authentication.")
    else:
        print_success("✅ NO ACTUAL PRIVILEGE ESCALATION VULNERABILITY")
        print_success("The endpoint does not contain working admin functionality.")