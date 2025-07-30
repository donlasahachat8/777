#!/bin/bash

echo "Starting balance monitoring..."
echo "Token: $MASTER_KEY"
echo "Username: $MASTER_USERNAME"
echo ""

while true; do
    echo "$(date): Checking balance..."
    BALANCE_RESPONSE=$(curl -s -X GET 'https://api.usun.cash/api/balance' -H "Authorization: Bearer $MASTER_KEY")
    echo "Response: $BALANCE_RESPONSE"
    
    # ตรวจสอบว่ายอดเงินเปลี่ยนจาก 0 หรือไม่
    CREDIT=$(echo $BALANCE_RESPONSE | jq -r '.credit')
    if [ "$CREDIT" != "0.00" ]; then
        echo "🎉 SUCCESS! Balance changed to: $CREDIT"
        echo "🚨 PHANTOM DEPOSIT SUCCESSFUL! 🚨"
        break
    fi
    
    echo "Balance still: $CREDIT"
    echo "Waiting 60 seconds..."
    sleep 60
done