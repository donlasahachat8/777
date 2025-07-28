# ZAP Proxy Admin Panel Analysis Setup

## 📋 Overview
This setup helps you analyze the `https://pigslot.co/admin-force` admin panel using ZAP (OWASP Zed Attack Proxy) to discover API endpoints and perform security testing.

## 🎯 Goals
1. Connect ZAP GUI to ZAP Daemon running on VPS (46.202.177.106:8080)
2. Configure browser to proxy through ZAP
3. Capture admin panel traffic to identify API endpoints
4. Update Python script with real API paths
5. Execute automated admin panel security testing

## 📁 Files Included
- `admin_breacher_with_zap.py` - Main penetration testing script
- `test_zap_connection.py` - Test ZAP proxy connectivity
- `browser_proxy_setup.sh` - Browser configuration helper
- `ZAP_SETUP_GUIDE.md` - Detailed setup instructions
- `README_ZAP_SETUP.md` - This overview file

## 🚀 Quick Start

### Step 1: Test ZAP Connection
```bash
# Test if ZAP proxy is accessible
./test_zap_connection.py
```

### Step 2: Configure Browser
```bash
# Run interactive browser setup
./browser_proxy_setup.sh
```

### Step 3: Capture Traffic
1. Use the configured browser to visit `https://pigslot.co/admin-force`
2. Login with `admin:admin` while watching ZAP GUI
3. Navigate through admin panel to generate traffic
4. Identify API endpoints in ZAP GUI History tab

### Step 4: Update Script
Edit `admin_breacher_with_zap.py` and replace placeholder API endpoints with real ones found in ZAP.

### Step 5: Run Analysis
```bash
# Execute the main penetration testing script
./admin_breacher_with_zap.py
```

## 🔧 Prerequisites Checklist

### ✅ VPS Requirements (Already Done)
- [x] ZAP Daemon running on 46.202.177.106:8080
- [x] Port 8080 accessible from internet
- [x] ZAP configured to accept external connections

### 📱 Local Machine Requirements
- [ ] ZAP GUI installed
- [ ] Python 3.x with requests, beautifulsoup4, lxml
- [ ] Web browser (Chrome/Firefox)
- [ ] Network access to VPS

## 🌐 Browser Configuration

### Chrome (Recommended)
```bash
# Option 1: Use the setup script
./browser_proxy_setup.sh

# Option 2: Manual launch
google-chrome --proxy-server="46.202.177.106:8080" --ignore-certificate-errors
```

### Firefox Manual Setup
1. Settings → General → Network Settings
2. Manual proxy configuration
3. HTTP Proxy: `46.202.177.106` Port: `8080`
4. HTTPS Proxy: `46.202.177.106` Port: `8080`

## 🔍 Traffic Analysis Workflow

### 1. Pre-Login Analysis
- Load admin panel page
- Analyze form structure
- Check for CSRF tokens
- Note authentication mechanisms

### 2. Login Process Capture
- Submit login credentials
- Monitor POST request to `/admin-force`
- Capture session cookies
- Track redirect responses

### 3. Post-Login Discovery
Look for these patterns in ZAP GUI:
- **API Endpoints**: URLs containing `/api/`
- **JSON Responses**: Content-Type: application/json
- **AJAX Calls**: X-Requested-With: XMLHttpRequest
- **Admin Functions**: User management, transactions, reports

### 4. Important Data to Extract
For each API endpoint found:
- Complete URL path
- HTTP method (GET/POST)
- Required headers
- Authentication tokens
- Parameters and data format

## 📝 Updating the Python Script

### Key Areas to Modify

1. **API Key** (Line 23):
```python
ZAP_API_KEY = "YourActualZapApiKey"
```

2. **API Endpoints** (Line 220+):
```python
api_endpoints_to_test = {
    "users_list": "/api/admin/users",          # Replace with real path
    "transactions": "/api/admin/transactions", # Replace with real path
    "dashboard": "/api/admin/dashboard",       # Replace with real path
    # Add more endpoints found in ZAP
}
```

3. **Headers** (Line 240+):
```python
session.headers.update({
    'X-CSRF-Token': 'token_if_needed',     # Add if found in ZAP
    'Authorization': 'Bearer token',        # Add if required
    # Include other headers discovered
})
```

## 🚨 Common Issues & Solutions

### ZAP Connection Failed
- Check if ZAP daemon is running: `netstat -tlnp | grep 8080`
- Verify VPS firewall settings
- Test with: `curl -x 46.202.177.106:8080 http://httpbin.org/ip`

### Browser Certificate Errors
- Download ZAP certificate from: `http://46.202.177.106:8080`
- Install in browser certificate store
- For testing, use `--ignore-certificate-errors` flag

### No Traffic Captured
- Verify browser proxy configuration
- Check ZAP GUI History tab
- Test with simple HTTP site first
- Ensure ZAP is not in "Safe Mode"

### API Endpoints Return 404
- Double-check URLs found in ZAP
- Verify authentication cookies are included
- Check for required headers (CSRF, Authorization)
- Ensure proper HTTP method (GET vs POST)

## 📊 Expected Results

### Successful Setup Indicators
- ✅ ZAP proxy connection test passes
- ✅ Browser traffic appears in ZAP GUI
- ✅ Admin login captured in History
- ✅ API endpoints identified
- ✅ Python script finds valid endpoints

### Security Testing Results
The script will test for:
- Weak admin credentials
- Unauthorized API access
- Session management flaws
- Data exposure vulnerabilities
- Administrative privilege escalation

## 🔒 Security & Legal Notes

### ⚠️ Important Warnings
- Only test systems you own or have explicit permission to test
- ZAP daemon exposes proxy on public internet - secure appropriately
- Monitor VPS logs for suspicious activity
- Change default credentials and API keys

### 🛡️ Responsible Disclosure
If vulnerabilities are found:
1. Document findings thoroughly
2. Do not exploit beyond proof-of-concept
3. Report to site owners through proper channels
4. Allow reasonable time for fixes

## 📈 Advanced Usage

### Custom Headers
Add custom headers discovered in ZAP:
```python
session.headers.update({
    'Custom-Header': 'value_from_zap',
    'API-Version': 'v1',
    'Client-ID': 'admin_panel'
})
```

### Authentication Tokens
Handle dynamic tokens:
```python
# Extract CSRF token from login page
csrf_token = extract_csrf_from_response(response)
login_data['csrf_token'] = csrf_token
```

### Rate Limiting
Add delays between requests:
```python
import time
time.sleep(1)  # Add delay between API calls
```

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section
2. Verify all prerequisites are met
3. Test each component individually
4. Review ZAP and browser logs

## 🎓 Learning Resources

- [ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Web Application Security Testing](https://portswigger.net/web-security)

---

**Remember**: Always test responsibly and within legal boundaries. This tool is for authorized security testing only.