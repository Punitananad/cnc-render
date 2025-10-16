#!/bin/bash

# Frontend Smoke Test Script (Bash version)
# Alternative to Node.js version for environments without Node

echo "🚀 Starting Frontend Smoke Tests..."

BASE_URL="http://localhost:5000"
SCREENSHOT_DIR="./screenshots"
TEST_RESULTS=()

# Create screenshot directory
mkdir -p "$SCREENSHOT_DIR"

# Function to test a URL
test_url() {
    local name="$1"
    local url="$2"
    local expected_elements="$3"
    
    echo "📄 Testing: $name"
    
    # Use curl to test if page loads
    response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$url" 2>/dev/null)
    
    if [ "$response" = "200" ] || [ "$response" = "302" ]; then
        echo "✅ $name: Page loads (HTTP $response)"
        TEST_RESULTS+=("PASS: $name")
        return 0
    else
        echo "❌ $name: Failed to load (HTTP $response)"
        TEST_RESULTS+=("FAIL: $name")
        return 1
    fi
}

# Function to check if Flask server is running
check_server() {
    echo "🔍 Checking if Flask server is running..."
    
    if curl -s "$BASE_URL" > /dev/null 2>&1; then
        echo "✅ Server is running at $BASE_URL"
        return 0
    else
        echo "❌ Server is not running at $BASE_URL"
        echo "Please start the Flask server with: python app.py"
        return 1
    fi
}

# Function to test static files
test_static_files() {
    echo "📁 Testing static files..."
    
    local static_files=(
        "/static/css/gentelella.css"
        "/static/css/gentelella-theme.css"
        "/static/js/gentelella.js"
        "/static/js/app.js"
    )
    
    for file in "${static_files[@]}"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$file" 2>/dev/null)
        if [ "$response" = "200" ]; then
            echo "✅ Static file: $file"
        else
            echo "❌ Static file missing: $file (HTTP $response)"
        fi
    done
}

# Main test execution
main() {
    # Check if server is running
    if ! check_server; then
        exit 1
    fi
    
    echo ""
    
    # Test static files
    test_static_files
    echo ""
    
    # Test main pages
    test_url "Home" "/" "navbar,main-content"
    test_url "Login" "/login" "form,input"
    test_url "Register" "/register" "form,input"
    test_url "Dashboard" "/calculatentrade_journal/dashboard" "container"
    test_url "Trades" "/calculatentrade_journal/trades" "table,nav"
    test_url "Admin Login" "/admin/login" "form"
    
    echo ""
    echo "📊 Test Results Summary:"
    
    passed=0
    total=0
    
    for result in "${TEST_RESULTS[@]}"; do
        echo "$result"
        total=$((total + 1))
        if [[ $result == PASS* ]]; then
            passed=$((passed + 1))
        fi
    done
    
    echo ""
    echo "Passed: $passed/$total"
    
    if [ $passed -eq $total ]; then
        echo "🎉 All tests passed!"
        exit 0
    else
        echo "❌ Some tests failed"
        exit 1
    fi
}

# Run main function
main "$@"