#!/usr/bin/env python3
"""Database initialization script for production deployment"""

import os
import sys
from app import app, db

def init_database():
    """Initialize database tables in correct order"""
    with app.app_context():
        try:
            # Step 1: Create main application tables first
            print("Creating main application tables...")
            db.create_all()
            print("✓ Main database tables created successfully")
            
            # Step 2: Initialize blueprint databases (they depend on main tables)
            print("Initializing blueprint databases...")
            
            try:
                from admin_blueprint import init_admin_db
                init_admin_db(db)
                print("✓ Admin database initialized")
            except Exception as e:
                print(f"⚠ Admin database init failed: {e}")
            
            try:
                from employee_dashboard_bp import init_employee_dashboard_db
                init_employee_dashboard_db(db)
                print("✓ Employee database initialized")
            except Exception as e:
                print(f"⚠ Employee database init failed: {e}")
            
            try:
                from mentor import init_mentor_db
                init_mentor_db(db)
                print("✓ Mentor database initialized")
            except Exception as e:
                print(f"⚠ Mentor database init failed: {e}")
            
            print("✓ Database initialization completed successfully")
                
        except Exception as e:
            print(f"✗ Database initialization failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    init_database()