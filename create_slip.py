#!/usr/bin/env python3
from PIL import Image, ImageDraw, ImageFont
import os
from datetime import datetime
import secrets

# สร้างภาพสีขาว
img = Image.new('RGB', (800, 600), color='white')
draw = ImageDraw.Draw(img)

# ข้อความที่จะเขียน
text = f"""KBank Transfer Slip

From: Krit Phasuk
To: Company Account
Amount: 999.87 THB
Date: {datetime.now().strftime('%Y-%m-%d')}
Time: {datetime.now().strftime('%H:%M:%S')}

Reference: {secrets.token_hex(8)}"""

# เขียนข้อความลงบนภาพ
draw.text((50, 50), text, fill='black')

# บันทึกไฟล์
img.save('slip.jpg')
print("Created slip.jpg")