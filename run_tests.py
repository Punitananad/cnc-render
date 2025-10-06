#!/usr/bin/env python3
"""
Frontend Smoke Test Script (Python version)
Tests Flask routes and template rendering
"""

import os
import sys
import requests
import time
from urllib.parse import urljoin

# Test configuration
BASE_URL = 'http://localhost:5000'
TIMEOUT = 10

# Test routes and expected content
TEST_ROUTES = [
    {
        'name': 'Home Page',
        'path': '/',
        'expected_content': ['Calculate N Trade', 'Trading Calculators', 'Trading Journal'],
        'status_codes': [200]
    },
    {
        'name': 'Login Page',
        'path': '/login',
        'expected_content': ['Login', 'Email', 'Password'],
        'status_codes': [200]
    },
    {
        'name': 'Register Page',
        'path': '/register',
        'expected_content': ['Register', 'Email', 'Password'],
        'status_codes': [200]
    },
    {
        'name': 'Calculator Page',
        'path': '/calculator',
        'expected_content': ['Calculator', 'Trading'],
        'status_codes': [200, 302]  # May redirect if not authenticated
    },
    {
        'name': 'AI Assistant',
        'path': '/calculatentrade_journal/ai_summaries',
        'expected_content': ['AI Trading Assistant', 'Quick Questions', 'chatMessages'],
        'status_codes': [200, 302]  # May redirect if not authenticated
    },
    {
        'name': 'Calculator Home',
        'path': '/calculator',
        'expected_content': ['Trading Calculators', 'Intraday Calculator', 'F&O Calculator'],
        'status_codes': [200]
    },
    {
        'name': 'Intraday Calculator',
        'path': '/intraday_calculator',
        'expected_content': ['Intraday Trade Calculator', 'Average Price', 'Quantity'],
        'status_codes': [200]
    },
    {
        'name': 'Admin Login',
        'path': '/admin/login',
        'expected_content': ['Admin', 'Login'],
        'status_codes': [200]
    },
    {
        'name': 'Employee Login',
        'path': '/employee/login',
        'expected_content': ['Employee', 'Login'],
        'status_codes': [200]
    }
]

# Static files to test
STATIC_FILES = [
    '/static/css/gentelella.css',
    '/static/css/gentelella-theme.css',
    '/static/js/gentelella.js',
    '/static/js/app.js'
]

def test_server_running():
    """Test if Flask server is running"""
    print("🔍 Checking if Flask server is running...")
    try:
        response = requests.get(BASE_URL, timeout=TIMEOUT)
        print(f"✅ Server is running at {BASE_URL}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Server is not running at {BASE_URL}")
        print(f"   Error: {e}")
        print("   Please start the Flask server with: python app.py")
        return False

def test_route(route_info):
    """Test a single route"""
    print(f"📄 Testing: {route_info['name']}")
    
    try:
        url = urljoin(BASE_URL, route_info['path'])
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        
        # Check status code
        if response.status_code not in route_info['status_codes']:
            print(f"❌ {route_info['name']}: Unexpected status code {response.status_code}")
            return False
        
        # Check content (only for 200 responses)
        if response.status_code == 200:
            content = response.text.lower()
            missing_content = []
            
            for expected in route_info['expected_content']:
                if expected.lower() not in content:
                    missing_content.append(expected)
            
            if missing_content:
                print(f"❌ {route_info['name']}: Missing content: {', '.join(missing_content)}")
                return False
        
        print(f"✅ {route_info['name']}: OK (HTTP {response.status_code})")
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"❌ {route_info['name']}: Request failed - {e}")
        return False

def test_static_files():
    """Test static file accessibility"""
    print("📁 Testing static files...")
    
    results = []
    for static_file in STATIC_FILES:
        try:
            url = urljoin(BASE_URL, static_file)
            response = requests.get(url, timeout=TIMEOUT)
            
            if response.status_code == 200:
                print(f"✅ Static file: {static_file}")
                results.append(True)
            else:
                print(f"❌ Static file missing: {static_file} (HTTP {response.status_code})")
                results.append(False)
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Static file error: {static_file} - {e}")
            results.append(False)
    
    return results

def test_template_rendering():
    """Test that templates render without errors"""
    print("🎨 Testing template rendering...")
    
    # Test a few key templates by checking for template-specific content
    template_tests = [
        {
            'path': '/',
            'template_indicators': ['simple_base.html', 'navbar', 'footer'],
            'name': 'Home Template'
        },
        {
            'path': '/login',
            'template_indicators': ['simple_base.html', 'form'],
            'name': 'Login Template'
        }
    ]
    
    results = []
    for test in template_tests:
        try:
            url = urljoin(BASE_URL, test['path'])
            response = requests.get(url, timeout=TIMEOUT)
            
            if response.status_code == 200:
                # Check if page rendered properly (no template errors)
                content = response.text
                if 'TemplateNotFound' in content or 'Jinja2' in content:
                    print(f"❌ {test['name']}: Template error detected")
                    results.append(False)
                else:
                    print(f"✅ {test['name']}: Rendered successfully")
                    results.append(True)
            else:
                print(f"❌ {test['name']}: HTTP {response.status_code}")
                results.append(False)
                
        except requests.exceptions.RequestException as e:
            print(f"❌ {test['name']}: {e}")
            results.append(False)
    
    return results

def main():
    """Run all tests"""
    print("🚀 Starting Frontend Smoke Tests...\n")
    
    # Check if server is running
    if not test_server_running():
        return False
    
    print()
    
    # Test static files
    static_results = test_static_files()
    print()
    
    # Test routes
    route_results = []
    for route in TEST_ROUTES:
        result = test_route(route)
        route_results.append(result)
    
    print()
    
    # Test template rendering
    template_results = test_template_rendering()
    print()
    
    # Calculate results
    all_results = static_results + route_results + template_results
    passed = sum(all_results)
    total = len(all_results)
    
    # Print summary
    print("📊 Test Results Summary:")
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("🎉 All tests passed!")
        return True
    else:
        print("❌ Some tests failed")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)