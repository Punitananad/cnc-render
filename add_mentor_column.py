import sqlite3
import os

# Path to your database
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'calculatentrade.db')

def add_mentor_column():
    """Add mentor_id column to existing coupon table"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(coupon)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'mentor_id' not in columns:
            # Add the mentor_id column
            cursor.execute("ALTER TABLE coupon ADD COLUMN mentor_id INTEGER")
            conn.commit()
            print("Successfully added mentor_id column to coupon table")
        else:
            print("mentor_id column already exists in coupon table")
        
        conn.close()
        
    except Exception as e:
        print(f"Error adding mentor_id column: {e}")

if __name__ == "__main__":
    add_mentor_column()