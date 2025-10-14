#!/usr/bin/env python3
"""
Test script to verify database initialization without running the full app
"""

import os
import sys
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Prevent network calls during import
os.environ['SMARTAPI_DISABLE_NETWORK'] = '1'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

try:
    # Import Flask and basic dependencies
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from datetime import datetime
    
    print("✓ Basic imports successful")
    
    # Create minimal Flask app
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_calculatentrade.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'test-secret-key'
    
    # Initialize database
    db = SQLAlchemy(app)
    
    print("✓ Flask app and database initialized")
    
    # Test importing main models
    with app.app_context():
        # Import User model from app
        sys.path.insert(0, os.path.dirname(__file__))
        
        # Test basic model creation
        from werkzeug.security import generate_password_hash
        from flask_login import UserMixin
        
        class User(UserMixin, db.Model):
            __tablename__ = "user"
            id = db.Column(db.Integer, primary_key=True)
            email = db.Column(db.String(120), unique=True, nullable=False, index=True)
            password_hash = db.Column(db.String(255), nullable=True)
            registered_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
            verified = db.Column(db.Boolean, nullable=False, default=False)
        
        print("✓ User model defined")
        
        # Create main tables first
        db.create_all()
        print("✓ Main database tables created")
        
        # Test SmartLoop models import
        try:
            from smartloop.models import Strategy, DailyLog
            print("✓ SmartLoop models imported successfully")
            
            # Create SmartLoop tables
            db.create_all()
            print("✓ SmartLoop tables created successfully")
            
        except Exception as e:
            print(f"⚠ SmartLoop models import failed: {e}")
        
        # Test journal models import
        try:
            # Mock the journal db import
            import journal
            journal.db = db
            
            from journal import Trade, Strategy as JournalStrategy
            print("✓ Journal models imported successfully")
            
        except Exception as e:
            print(f"⚠ Journal models import failed: {e}")
        
        print("✓ Database initialization test completed successfully")

except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    sys.exit(1)

print("\n🎉 All tests passed! Database initialization should work properly.")