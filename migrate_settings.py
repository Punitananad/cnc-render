#!/usr/bin/env python3
"""
Database migration script to add user_settings table
"""

import sqlite3
import os
from datetime import datetime

def migrate_settings_table():
    """Add user_settings table to existing database"""
    
    # Database path
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'calculatentrade.db')
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if user_settings table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='user_settings'
        """)
        
        if cursor.fetchone():
            print("user_settings table already exists")
            conn.close()
            return True
        
        # Create user_settings table
        cursor.execute("""
            CREATE TABLE user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email_notifications BOOLEAN DEFAULT 1,
                theme VARCHAR(20) DEFAULT 'light',
                timezone VARCHAR(50) DEFAULT 'Asia/Kolkata',
                default_calculator VARCHAR(20) DEFAULT 'intraday',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        """)
        
        print("✓ Created user_settings table")
        
        # Create default settings for existing users
        cursor.execute("SELECT id FROM user")
        users = cursor.fetchall()
        
        for user in users:
            user_id = user[0]
            cursor.execute("""
                INSERT INTO user_settings (user_id, email_notifications, theme, timezone, default_calculator)
                VALUES (?, 1, 'light', 'Asia/Kolkata', 'intraday')
            """, (user_id,))
        
        print(f"✓ Created default settings for {len(users)} existing users")
        
        conn.commit()
        conn.close()
        
        print("✓ Settings migration completed successfully")
        return True
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    print("Starting settings table migration...")
    success = migrate_settings_table()
    
    if success:
        print("\nMigration completed successfully!")
        print("You can now use the settings functionality.")
    else:
        print("\nMigration failed!")
        print("Please check the error messages above.")