#!/usr/bin/env python3
"""
Monitor the payload testing progress
"""

import os
import time
import json
import glob
from datetime import datetime

def monitor_testing():
    print("🔍 Monitoring Payload Testing Progress")
    print("=" * 50)
    
    while True:
        try:
            # Check for result files
            result_files = glob.glob("improved_payload_results_*.json")
            evidence_files = glob.glob("improved_evidence_*.txt")
            
            if result_files:
                # Read the latest result file
                latest_result = max(result_files, key=os.path.getctime)
                print(f"\n📊 Found result file: {latest_result}")
                
                with open(latest_result, 'r') as f:
                    data = json.load(f)
                    
                summary = data['summary']
                print(f"   Tests Conducted: {summary['total_tests_conducted']}")
                print(f"   Tests Planned: {summary['max_tests_planned']}")
                print(f"   Successful: {summary['successful_payloads_found']}")
                print(f"   Blocked: {summary['blocked_requests']}")
                print(f"   Errors: {summary['error_requests']}")
                print(f"   Success Rate: {summary['success_rate']:.2f}%")
                print(f"   Block Rate: {summary['block_rate']:.2f}%")
                
                if summary['successful_payloads_found'] > 0:
                    print(f"\n🎯 SUCCESSFUL PAYLOADS:")
                    for i, success in enumerate(data['successful_payloads'], 1):
                        print(f"   {i}. Type: {success['payload_type']}")
                        print(f"      Payload: {success['payload'][:60]}...")
                        print(f"      URL: {success['url']}")
                        print(f"      Parameter: {success['parameter']}")
                        print(f"      Status: {success['status_code']}")
                
                if summary['tests_completed']:
                    print(f"\n✅ Testing completed!")
                    break
                else:
                    print(f"\n⏳ Testing in progress...")
            else:
                print(f"⏳ Waiting for results... {datetime.now().strftime('%H:%M:%S')}")
            
            # Check if process is still running
            import subprocess
            result = subprocess.run(['pgrep', '-f', 'improved_payload_tester.py'], 
                                  capture_output=True, text=True)
            
            if not result.stdout.strip():
                print("❌ Testing process not found - may have completed or crashed")
                break
            
            time.sleep(30)  # Check every 30 seconds
            
        except KeyboardInterrupt:
            print("\n⚠️ Monitoring stopped by user")
            break
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")
            time.sleep(10)
    
    print("\n🏁 Monitoring completed")

if __name__ == "__main__":
    monitor_testing()