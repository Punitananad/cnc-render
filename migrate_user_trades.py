#!/usr/bin/env python3
"""
Database migration script to add user_id column to trade tables
"""

import sqlite3
import os

def migrate_trade_tables():
    """Add user_id column to existing trade tables"""
    
    # Database path
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'calculatentrade.db')
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # List of trade tables to update
        trade_tables = [
            'intraday_trades',
            'delivery_trades', 
            'swing_trades',
            'mtf_trades',
            'fo_trades'
        ]
        
        for table in trade_tables:
            # Check if table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?
            """, (table,))
            
            if not cursor.fetchone():
                print(f"Table {table} does not exist, skipping...")
                continue
            
            # Check if user_id column already exists
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'user_id' in columns:
                print(f"user_id column already exists in {table}")
                continue
            
            # Add user_id column
            cursor.execute(f"""
                ALTER TABLE {table} 
                ADD COLUMN user_id INTEGER REFERENCES user(id)
            """)
            
            print(f"Added user_id column to {table}")
        
        conn.commit()
        conn.close()
        
        print("Trade tables migration completed successfully")
        return True
        
    except Exception as e:
        print(f"Migration failed: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    print("Starting trade tables migration...")
    success = migrate_trade_tables()
    
    if success:
        print("\nMigration completed successfully!")
        print("Trade tables now have user_id columns.")
    else:
        print("\nMigration failed!")
        print("Please check the error messages above.")