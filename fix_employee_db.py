#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from employee_dashboard_bp import init_employee_dashboard_db

def fix_employee_database():
    with app.app_context():
        print("Fixing employee dashboard database...")
        
        try:
            # Drop existing employee tables
            tables_to_drop = [
                'emp_user_session',
                'emp_audit_log', 
                'emp_dashboard_employee',
                'emp_role'
            ]
            
            for table in tables_to_drop:
                try:
                    db.engine.execute(f'DROP TABLE IF EXISTS {table}')
                    print(f"Dropped table: {table}")
                except Exception as e:
                    print(f"Could not drop {table}: {e}")
            
            # Reinitialize employee dashboard
            print("Reinitializing employee dashboard...")
            init_employee_dashboard_db(db)
            
            # Verify tables were created
            result = db.engine.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'emp_%'")
            created_tables = [row[0] for row in result]
            print(f"Created employee tables: {created_tables}")
            
            # Check emp_dashboard_employee structure
            if 'emp_dashboard_employee' in created_tables:
                result = db.engine.execute('PRAGMA table_info(emp_dashboard_employee)')
                columns = [(row[1], row[2]) for row in result]
                print(f"emp_dashboard_employee columns: {columns}")
            
            print("Employee database fixed successfully!")
            return True
            
        except Exception as e:
            print(f"Error fixing employee database: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    fix_employee_database()