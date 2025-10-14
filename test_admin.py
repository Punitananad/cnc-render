#!/usr/bin/env python3
"""Test script to check admin routes"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from app import app, db
from admin_blueprint import init_admin_db

def test_admin_routes():
    """Test admin routes and database"""
    with app.app_context():
        try:
            # Initialize admin database
            init_admin_db(db)
            print("Admin database initialized successfully")
            
            # Test coupon query
            from admin_blueprint import Coupon
            coupons = Coupon.query.all()
            print(f"Coupon query successful - found {len(coupons)} coupons")
            
            print("All admin routes should work now")
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False

if __name__ == "__main__":
    success = test_admin_routes()
    if success:
        print("\nStarting Flask app...")
        app.run(host="0.0.0.0", port="5000", debug=True)
    else:
        print("\nFix errors before starting app")