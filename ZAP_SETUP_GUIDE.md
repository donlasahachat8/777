# ZAP GUI Setup Guide for Remote Daemon Connection

## Overview
This guide will help you set up ZAP GUI on your local machine to connect to the ZAP Daemon running on your VPS (46.202.177.106:8080) and analyze traffic from pigslot.co admin panel.

## Prerequisites
- ZAP Daemon is already running on VPS (46.202.177.106:8080) ✅
- Local machine with ZAP GUI installed
- Browser for testing (Chrome/Firefox recommended)

## Step 1: Download and Install ZAP GUI (if not already installed)

### Windows:
```bash
# Download from: https://www.zaproxy.org/download/
# Install ZAP_2_15_0_windows.exe
```

### Linux:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install zaproxy

# Or download latest from GitHub
wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2_15_0_Linux.tar.gz
tar -xzf ZAP_2_15_0_Linux.tar.gz
cd ZAP_2_15_0
./zap.sh
```

### macOS:
```bash
# Download from: https://www.zaproxy.org/download/
# Install ZAP_2_15_0.dmg
```

## Step 2: Configure ZAP GUI to Connect to Remote Daemon

### 2.1 Start ZAP GUI
- Launch ZAP GUI on your local machine
- **IMPORTANT**: Choose "No, I do not want to persist this session" when prompted

### 2.2 Connect to Remote Daemon
1. Go to `Tools` → `Options` → `Connection`
2. In the **Proxy** section:
   - **Address**: Leave as `localhost` (this is for local proxy)
   - **Port**: Leave as `8080` (this is for local proxy)
   
3. Go to `Tools` → `Options` → `API`
   - Check "Enable API"
   - Set **API Key**: `YourSecureApiKey123` (same as in your script)
   - **Important**: Make sure the API key matches the one in your Python script

### 2.3 Configure Connection to Remote Daemon
Since ZAP GUI needs to connect to the remote daemon, you have two options:

#### Option A: Direct Connection (if VPS allows direct API access)
1. Go to `File` → `New Session`
2. In ZAP GUI, manually change the connection settings to point to your VPS
3. This might require modifying ZAP configuration files

#### Option B: SSH Tunnel (Recommended)
Create an SSH tunnel to forward the remote ZAP daemon to your local machine:

```bash
# On your local machine, create SSH tunnel
ssh -L 8081:localhost:8080 root@46.202.177.106

# This forwards local port 8081 to remote port 8080
# Keep this terminal open while using ZAP
```

Then configure ZAP GUI to use `localhost:8081` for API connections.

## Step 3: Set Up Browser Proxy

### 3.1 Configure Browser to Use ZAP Proxy
Your browser needs to proxy through the ZAP daemon on the VPS.

#### Chrome/Chromium:
```bash
# Start Chrome with proxy settings
google-chrome --proxy-server="46.202.177.106:8080" --ignore-certificate-errors --ignore-ssl-errors

# Or use Chrome extension like "Proxy SwitchyOmega"
```

#### Firefox:
1. Go to `Settings` → `General` → `Network Settings`
2. Select "Manual proxy configuration"
3. **HTTP Proxy**: `46.202.177.106` **Port**: `8080`
4. **HTTPS Proxy**: `46.202.177.106` **Port**: `8080`
5. Check "Use this proxy server for all protocols"

### 3.2 Install ZAP Certificate (Important for HTTPS)
1. In your browser, go to: `http://46.202.177.106:8080`
2. Click on "CA Certificate" to download ZAP's root certificate
3. Install this certificate in your browser:
   - **Chrome**: Settings → Privacy and Security → Security → Manage Certificates → Authorities → Import
   - **Firefox**: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import

## Step 4: Test Connection and Capture Traffic

### 4.1 Verify ZAP Connection
1. In ZAP GUI, check if you can see traffic in the **History** tab
2. Test by browsing to a simple HTTP site first
3. Verify HTTPS traffic is being captured

### 4.2 Navigate to Target Site
1. In your configured browser, go to: `https://pigslot.co/admin-force`
2. **Important**: Do NOT login yet - just load the page
3. Check ZAP GUI **History** tab to see if the request appears

### 4.3 Manual Login for Traffic Analysis
1. On the admin login page (`https://pigslot.co/admin-force`)
2. Login with credentials: `admin` / `admin`
3. **Watch ZAP GUI carefully** during login process
4. Navigate through the admin panel to generate more traffic

## Step 5: Analyze Captured Traffic in ZAP GUI

### 5.1 Look for Login Requests
In ZAP History tab, find:
- **POST request** to `/admin-force` (login submission)
- Check **Request** tab for form data
- Check **Response** tab for success indicators
- Note any **Set-Cookie** headers

### 5.2 Find API Endpoints
After successful login, look for:
- Requests with `/api/` in the URL
- **JSON responses** (Content-Type: application/json)
- **AJAX requests** (X-Requested-With: XMLHttpRequest)
- Requests that return user data, transactions, etc.

### 5.3 Important Information to Note:
For each useful API endpoint, record:
- **Full URL path** (e.g., `/api/admin/users`)
- **HTTP Method** (GET, POST, etc.)
- **Required Headers** (especially cookies, authorization)
- **Parameters** (query string or POST data)
- **Response type** (JSON, HTML, etc.)

## Step 6: Update Python Script with Real API Endpoints

### 6.1 Replace Placeholder Endpoints
Edit the `admin_breacher_with_zap.py` file and replace these sections:

```python
# Update ZAP_API_KEY with your actual API key
ZAP_API_KEY = "YourActualApiKeyFromZAP"

# Replace with actual API endpoints found in ZAP
api_endpoints_to_test = {
    "users_list": "/api/admin/users",          # Replace with real path
    "transactions_history": "/api/transactions", # Replace with real path
    "dashboard_stats": "/api/dashboard/stats",   # Replace with real path
    # Add more endpoints you found
}
```

### 6.2 Add Required Headers
If you found special headers in ZAP, add them:

```python
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'Authorization': 'Bearer TOKEN_IF_NEEDED',  # If required
    'X-CSRF-Token': 'TOKEN_IF_NEEDED',          # If required
    # Add other headers you found in ZAP
})
```

## Step 7: Run the Updated Script

```bash
# Make sure script is executable
chmod +x admin_breacher_with_zap.py

# Run the script
./admin_breacher_with_zap.py
```

## Troubleshooting

### ZAP Connection Issues:
- Ensure ZAP daemon is running on VPS: `netstat -tlnp | grep 8080`
- Check VPS firewall: `ufw status` or `iptables -L`
- Verify ZAP daemon allows external connections

### Browser Proxy Issues:
- Clear browser cache and cookies
- Disable other proxy extensions
- Try different browser if issues persist

### Certificate Issues:
- Make sure ZAP certificate is properly installed
- Try browsing to `http://46.202.177.106:8080` to download certificate again
- Check browser certificate settings

### No Traffic Captured:
- Verify proxy settings in browser
- Check if ZAP daemon is accepting connections
- Try browsing to a simple HTTP site first

## Expected Results

After successful setup, you should see:
1. ✅ ZAP GUI connected to remote daemon
2. ✅ Browser traffic flowing through ZAP
3. ✅ Admin login captured in ZAP History
4. ✅ API endpoints identified
5. ✅ Python script successfully testing real endpoints

## Security Notes
- Only use this for authorized penetration testing
- The ZAP daemon is exposed on the internet - secure it properly
- Change default API keys and passwords
- Monitor VPS logs for suspicious activity

## Next Steps
Once you have identified the real API endpoints from ZAP:
1. Update the Python script with actual paths
2. Test the script to confirm it works with real endpoints
3. Analyze the results for security vulnerabilities
4. Generate comprehensive penetration testing report