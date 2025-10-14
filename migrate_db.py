#!/usr/bin/env python3
"""
Database migration script to add subscription columns
"""
import sqlite3
import os

def migrate_database():
    db_path = 'instance/calculatentrade.db'
    
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found. Creating new database...")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Add subscription columns to user table
        print("Adding subscription_active column...")
        cursor.execute("ALTER TABLE user ADD COLUMN subscription_active BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("subscription_active column already exists")
        else:
            print(f"Error adding subscription_active: {e}")
    
    try:
        print("Adding subscription_expires column...")
        cursor.execute("ALTER TABLE user ADD COLUMN subscription_expires DATETIME")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("subscription_expires column already exists")
        else:
            print(f"Error adding subscription_expires: {e}")
    
    try:
        print("Adding subscription_type column...")
        cursor.execute("ALTER TABLE user ADD COLUMN subscription_type VARCHAR(20)")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("subscription_type column already exists")
        else:
            print(f"Error adding subscription_type: {e}")
    
    conn.commit()
    conn.close()
    print("Database migration completed successfully!")

if __name__ == "__main__":
    migrate_database()