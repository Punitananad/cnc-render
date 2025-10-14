#!/usr/bin/env python3

import os
import sqlite3

def recreate_employee_tables():
    db_path = 'instance/calculatentrade.db'
    
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Drop existing employee tables
        tables_to_drop = [
            'emp_user_session',
            'emp_audit_log', 
            'emp_dashboard_employee',
            'emp_role'
        ]
        
        for table in tables_to_drop:
            try:
                cursor.execute(f'DROP TABLE IF EXISTS {table}')
                print(f"Dropped table: {table}")
            except Exception as e:
                print(f"Could not drop {table}: {e}")
        
        # Create emp_role table
        cursor.execute('''
            CREATE TABLE emp_role (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(50) UNIQUE NOT NULL,
                description VARCHAR(200),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("Created emp_role table")
        
        # Create emp_dashboard_employee table
        cursor.execute('''
            CREATE TABLE emp_dashboard_employee (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(80) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role_id INTEGER NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                can_login BOOLEAN DEFAULT 1,
                last_login DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(80) DEFAULT 'admin',
                FOREIGN KEY (role_id) REFERENCES emp_role (id)
            )
        ''')
        print("Created emp_dashboard_employee table")
        
        # Create emp_audit_log table
        cursor.execute('''
            CREATE TABLE emp_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER NOT NULL,
                action VARCHAR(100) NOT NULL,
                target_type VARCHAR(50) NOT NULL,
                target_id INTEGER NOT NULL,
                meta JSON,
                ip_address VARCHAR(45),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_id) REFERENCES emp_dashboard_employee (id)
            )
        ''')
        print("Created emp_audit_log table")
        
        # Create emp_user_session table
        cursor.execute('''
            CREATE TABLE emp_user_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                ip_address VARCHAR(45),
                user_agent VARCHAR(500),
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        ''')
        print("Created emp_user_session table")
        
        # Insert default roles
        roles = [
            ('owner', 'System Owner - Full Access'),
            ('admin', 'Administrator - Manage Employees & Users'),
            ('employee', 'Employee - User Management Only'),
            ('user', 'Regular User')
        ]
        
        cursor.executemany('INSERT INTO emp_role (name, description) VALUES (?, ?)', roles)
        print("Inserted default roles")
        
        conn.commit()
        conn.close()
        
        print("Employee database tables recreated successfully!")
        return True
        
    else:
        print(f"Database file {db_path} not found")
        return False

if __name__ == "__main__":
    recreate_employee_tables()