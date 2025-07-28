#!/usr/bin/env python3

import requests
import sys
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ZAP Proxy Configuration
ZAP_PROXY_HOST = '46.202.177.106'
ZAP_PROXY_PORT = 8080

PROXIES = {
    'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
    'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
}

def print_info(message): print(f"\033[1;34m[+] {message}\033[0m")
def print_success(message): print(f"\033[1;32m[+] {message}\033[0m")
def print_error(message): print(f"\033[1;31m[-] {message}\033[0m")

def test_zap_connection():
    """Test ZAP proxy connection"""
    print_info("Testing ZAP Proxy Connection...")
    print_info(f"ZAP Proxy: {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}")
    
    try:
        # Test with a simple HTTP request
        session = requests.Session()
        session.proxies = PROXIES
        session.timeout = 10
        
        print_info("Testing HTTP connection...")
        response = session.get("http://httpbin.org/ip", verify=False)
        if response.status_code == 200:
            print_success("✅ HTTP proxy connection successful!")
            print_info(f"Response: {response.text.strip()}")
        else:
            print_error(f"HTTP test failed with status: {response.status_code}")
            return False
            
        print_info("Testing HTTPS connection...")
        response = session.get("https://httpbin.org/ip", verify=False)
        if response.status_code == 200:
            print_success("✅ HTTPS proxy connection successful!")
            print_info(f"Response: {response.text.strip()}")
        else:
            print_error(f"HTTPS test failed with status: {response.status_code}")
            return False
            
        return True
        
    except requests.exceptions.ConnectTimeout:
        print_error("❌ Connection timeout - ZAP daemon may not be running")
        return False
    except requests.exceptions.ProxyError as e:
        print_error(f"❌ Proxy error: {e}")
        return False
    except Exception as e:
        print_error(f"❌ Connection failed: {e}")
        return False

def test_target_access():
    """Test access to target site through proxy"""
    print_info("Testing access to target site...")
    
    try:
        session = requests.Session()
        session.proxies = PROXIES
        session.timeout = 15
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
        })
        
        # Test main site
        print_info("Testing https://pigslot.co/...")
        response = session.get("https://pigslot.co/", verify=False)
        if response.status_code == 200:
            print_success("✅ Main site accessible through proxy")
        else:
            print_error(f"Main site returned status: {response.status_code}")
            
        # Test admin panel
        print_info("Testing https://pigslot.co/admin-force...")
        response = session.get("https://pigslot.co/admin-force", verify=False)
        if response.status_code == 200:
            print_success("✅ Admin panel accessible through proxy")
            print_info(f"Response length: {len(response.text)} bytes")
            
            # Check if it looks like a login page
            if "login" in response.text.lower() or "username" in response.text.lower() or "password" in response.text.lower():
                print_success("✅ Admin login page detected")
            else:
                print_info("Page content doesn't appear to be a login form")
                
        else:
            print_error(f"Admin panel returned status: {response.status_code}")
            
        return True
        
    except Exception as e:
        print_error(f"❌ Target access failed: {e}")
        return False

def main():
    print_info("ZAP Connection Test Script")
    print_info("=" * 50)
    
    # Test 1: Basic proxy connection
    if not test_zap_connection():
        print_error("Basic proxy test failed. Check:")
        print_error("1. ZAP Daemon is running on VPS")
        print_error("2. Port 8080 is open and accessible")
        print_error("3. ZAP is configured to accept external connections")
        sys.exit(1)
    
    print_info("")
    
    # Test 2: Target site access
    if not test_target_access():
        print_error("Target site access failed")
        sys.exit(1)
    
    print_info("")
    print_success("🎉 All tests passed! ZAP proxy is working correctly.")
    print_info("You can now:")
    print_info("1. Set up your browser to use the ZAP proxy")
    print_info("2. Install ZAP certificate in your browser")
    print_info("3. Login to admin panel manually to capture traffic")
    print_info("4. Run the main admin_breacher_with_zap.py script")

if __name__ == "__main__":
    main()