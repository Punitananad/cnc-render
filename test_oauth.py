#!/usr/bin/env python3
"""
Test script to verify OAuth state parameter fix
"""
import os
import sys
import subprocess
import time
import requests
from urllib.parse import urlparse, parse_qs

def test_oauth_flow():
    """Test the OAuth flow to verify state parameter handling"""
    print("🔍 Testing OAuth State Parameter Fix")
    print("=" * 50)
    
    # Check if app is running
    try:
        response = requests.get("http://localhost:5000/", timeout=5)
        if response.status_code != 200:
            print("❌ App not responding on localhost:5000")
            return False
    except requests.exceptions.RequestException:
        print("❌ App not running on localhost:5000")
        print("Please start the app with: python app.py")
        return False
    
    print("✅ App is running on localhost:5000")
    
    # Test OAuth login endpoint
    try:
        # Create a session to maintain cookies
        session = requests.Session()
        
        # Access the OAuth login endpoint
        oauth_response = session.get("http://localhost:5000/oauth/login", allow_redirects=False)
        
        if oauth_response.status_code == 302:
            redirect_url = oauth_response.headers.get('Location')
            print(f"✅ OAuth login redirects to: {redirect_url[:100]}...")
            
            # Parse the redirect URL to check for state parameter
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            
            if 'state' in query_params:
                state_value = query_params['state'][0]
                print(f"✅ State parameter found: {state_value[:20]}...")
                
                # Check if redirect_uri is correct
                if 'redirect_uri' in query_params:
                    redirect_uri = query_params['redirect_uri'][0]
                    print(f"✅ Redirect URI: {redirect_uri}")
                    
                    if 'localhost:5000/auth/google/callback' in redirect_uri:
                        print("✅ Redirect URI matches expected callback")
                        return True
                    else:
                        print("❌ Redirect URI doesn't match expected callback")
                        return False
                else:
                    print("❌ No redirect_uri in OAuth URL")
                    return False
            else:
                print("❌ No state parameter in OAuth URL")
                return False
        else:
            print(f"❌ OAuth login returned status: {oauth_response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing OAuth flow: {e}")
        return False

def check_environment():
    """Check if required environment variables are set"""
    print("\n🔧 Checking Environment Configuration")
    print("=" * 50)
    
    required_vars = [
        'GOOGLE_CLIENT_ID',
        'GOOGLE_CLIENT_SECRET',
        'FLASK_SECRET'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
        else:
            print(f"✅ {var}: {'*' * 20}")
    
    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        return False
    
    print("✅ All required environment variables are set")
    return True

def main():
    """Main test function"""
    print("🚀 OAuth State Parameter Fix Verification")
    print("=" * 50)
    
    # Check environment
    if not check_environment():
        print("\n❌ Environment check failed")
        return False
    
    # Test OAuth flow
    if not test_oauth_flow():
        print("\n❌ OAuth flow test failed")
        return False
    
    print("\n✅ All tests passed!")
    print("\n📋 Manual Test Instructions:")
    print("1. Open browser to: http://localhost:5000/login")
    print("2. Click 'Continue with Google' button")
    print("3. Complete Google sign-in")
    print("4. Check console logs for state verification messages:")
    print("   - 'Saved state -> <value>'")
    print("   - 'Session state -> <value>'") 
    print("   - 'Returned state -> <value>'")
    print("5. Verify successful login without 'Invalid state parameter' error")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)