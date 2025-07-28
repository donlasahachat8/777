#!/bin/bash

# Browser Proxy Setup Script for ZAP
# This script helps configure browsers to use ZAP proxy

ZAP_HOST="46.202.177.106"
ZAP_PORT="8080"

echo "🔧 Browser Proxy Setup for ZAP Analysis"
echo "========================================"
echo "ZAP Proxy: $ZAP_HOST:$ZAP_PORT"
echo ""

# Function to print colored output
print_info() { echo -e "\033[1;34m[+] $1\033[0m"; }
print_success() { echo -e "\033[1;32m[+] $1\033[0m"; }
print_warning() { echo -e "\033[1;33m[!] $1\033[0m"; }
print_error() { echo -e "\033[1;31m[-] $1\033[0m"; }

# Check if browsers are installed
check_browsers() {
    print_info "Checking available browsers..."
    
    if command -v google-chrome &> /dev/null || command -v chromium-browser &> /dev/null || command -v chromium &> /dev/null; then
        print_success "Chrome/Chromium found"
        CHROME_AVAILABLE=true
    else
        print_warning "Chrome/Chromium not found"
        CHROME_AVAILABLE=false
    fi
    
    if command -v firefox &> /dev/null; then
        print_success "Firefox found"
        FIREFOX_AVAILABLE=true
    else
        print_warning "Firefox not found"
        FIREFOX_AVAILABLE=false
    fi
    
    echo ""
}

# Launch Chrome with proxy
launch_chrome_with_proxy() {
    print_info "Launching Chrome with ZAP proxy settings..."
    
    # Create a temporary user data directory
    TEMP_DIR="/tmp/chrome_zap_$(date +%s)"
    mkdir -p "$TEMP_DIR"
    
    # Chrome command line arguments
    CHROME_ARGS="--proxy-server=$ZAP_HOST:$ZAP_PORT \
                 --ignore-certificate-errors \
                 --ignore-ssl-errors \
                 --ignore-certificate-errors-spki-list \
                 --disable-web-security \
                 --user-data-dir=$TEMP_DIR \
                 --new-window"
    
    # Try different Chrome executables
    if command -v google-chrome &> /dev/null; then
        print_success "Starting Google Chrome with proxy..."
        google-chrome $CHROME_ARGS "https://pigslot.co/admin-force" &
    elif command -v chromium-browser &> /dev/null; then
        print_success "Starting Chromium with proxy..."
        chromium-browser $CHROME_ARGS "https://pigslot.co/admin-force" &
    elif command -v chromium &> /dev/null; then
        print_success "Starting Chromium with proxy..."
        chromium $CHROME_ARGS "https://pigslot.co/admin-force" &
    else
        print_error "Chrome/Chromium not found"
        return 1
    fi
    
    echo ""
    print_warning "⚠️  Important Chrome Notes:"
    print_warning "1. Chrome will show certificate warnings - click 'Advanced' → 'Proceed to site'"
    print_warning "2. Download ZAP certificate from: http://$ZAP_HOST:$ZAP_PORT"
    print_warning "3. Install certificate: Settings → Privacy → Security → Manage certificates → Authorities → Import"
    print_warning "4. Temporary profile will be deleted when Chrome closes"
    echo ""
}

# Firefox proxy instructions
firefox_proxy_instructions() {
    print_info "Firefox Manual Proxy Configuration:"
    echo ""
    echo "1. Open Firefox"
    echo "2. Go to: Settings → General → Network Settings"
    echo "3. Select 'Manual proxy configuration'"
    echo "4. Set HTTP Proxy: $ZAP_HOST  Port: $ZAP_PORT"
    echo "5. Set HTTPS Proxy: $ZAP_HOST  Port: $ZAP_PORT"
    echo "6. Check 'Use this proxy server for all protocols'"
    echo "7. Click 'OK'"
    echo ""
    print_warning "⚠️  Certificate Setup for Firefox:"
    echo "1. Go to: http://$ZAP_HOST:$ZAP_PORT"
    echo "2. Click 'CA Certificate' to download"
    echo "3. Settings → Privacy & Security → Certificates → View Certificates"
    echo "4. Authorities tab → Import → Select downloaded certificate"
    echo "5. Check 'Trust this CA to identify websites'"
    echo ""
}

# Download ZAP certificate
download_zap_cert() {
    print_info "Downloading ZAP root certificate..."
    
    # Try to download the certificate
    if curl -k -o "zap_root_ca.crt" "http://$ZAP_HOST:$ZAP_PORT/OTHER/core/other/rootcert/" 2>/dev/null; then
        print_success "✅ ZAP certificate downloaded as 'zap_root_ca.crt'"
        print_info "You can manually import this certificate into your browser"
    else
        print_warning "⚠️  Could not automatically download certificate"
        print_info "Manually download from: http://$ZAP_HOST:$ZAP_PORT"
    fi
    echo ""
}

# Test ZAP connection
test_zap_connection() {
    print_info "Testing ZAP proxy connection..."
    
    if curl -x "$ZAP_HOST:$ZAP_PORT" -s "http://httpbin.org/ip" &> /dev/null; then
        print_success "✅ ZAP proxy is accessible"
    else
        print_error "❌ Cannot connect to ZAP proxy"
        print_error "Make sure ZAP Daemon is running on $ZAP_HOST:$ZAP_PORT"
        return 1
    fi
    echo ""
}

# Main menu
show_menu() {
    echo "Choose an option:"
    echo "1. Test ZAP connection"
    echo "2. Launch Chrome with proxy (recommended)"
    echo "3. Show Firefox proxy instructions"
    echo "4. Download ZAP certificate"
    echo "5. All in one setup"
    echo "6. Exit"
    echo ""
    read -p "Enter choice [1-6]: " choice
}

# Main execution
main() {
    check_browsers
    
    while true; do
        show_menu
        
        case $choice in
            1)
                test_zap_connection
                ;;
            2)
                if [ "$CHROME_AVAILABLE" = true ]; then
                    launch_chrome_with_proxy
                else
                    print_error "Chrome/Chromium not available"
                fi
                ;;
            3)
                firefox_proxy_instructions
                ;;
            4)
                download_zap_cert
                ;;
            5)
                print_info "Running complete setup..."
                test_zap_connection && download_zap_cert
                if [ "$CHROME_AVAILABLE" = true ]; then
                    launch_chrome_with_proxy
                else
                    firefox_proxy_instructions
                fi
                ;;
            6)
                print_info "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice. Please try again."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        echo ""
    done
}

# Run the script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi