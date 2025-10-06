#!/usr/bin/env python3
"""
Simple test script to verify Flask can find and render home.html template
"""
import os
import sys
from flask import Flask, render_template

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_template():
    # Create minimal Flask app
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
    app = Flask(__name__, template_folder=template_dir)
    
    print(f"Template folder: {template_dir}")
    print(f"Template folder exists: {os.path.exists(template_dir)}")
    
    home_template = os.path.join(template_dir, 'home.html')
    print(f"Home template path: {home_template}")
    print(f"Home template exists: {os.path.exists(home_template)}")
    
    if os.path.exists(home_template):
        print(f"Home template size: {os.path.getsize(home_template)} bytes")
    
    # Test template rendering
    with app.app_context():
        try:
            result = render_template('home.html')
            print("✅ Template rendered successfully!")
            print(f"Rendered content length: {len(result)} characters")
            return True
        except Exception as e:
            print(f"❌ Template rendering failed: {e}")
            return False

if __name__ == '__main__':
    test_template()