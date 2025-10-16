#!/usr/bin/env python3
"""
Simple test to see if Flask app can start and serve home page
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    print("App imported successfully")
    
    # Test the home route
    with app.test_client() as client:
        response = client.get('/')
        print(f"Home route responded with status: {response.status_code}")
        if response.status_code == 200:
            print(f"Response length: {len(response.data)} bytes")
            print("Home page is working!")
        else:
            print(f"Error response: {response.data.decode()}")
            
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()