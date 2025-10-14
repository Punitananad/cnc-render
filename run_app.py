#!/usr/bin/env python3
"""
Proper application startup script with error handling
"""

import os
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def setup_environment():
    """Set up environment variables for safe startup"""
    # Prevent network calls during import
    os.environ['SMARTAPI_DISABLE_NETWORK'] = '1'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    # Set Flask environment
    if 'FLASK_ENV' not in os.environ:
        os.environ['FLASK_ENV'] = 'development'
    
    logger.info("Environment variables set up")

def initialize_database(app, db):
    """Initialize database with proper error handling"""
    with app.app_context():
        try:
            # Create main database tables first
            logger.info("Creating main database tables...")
            db.create_all()
            logger.info("✓ Main database tables created successfully")
            
            # Initialize blueprint databases
            try:
                from admin_blueprint import init_admin_db
                init_admin_db(db)
                logger.info("✓ Admin blueprint database initialized")
            except Exception as e:
                logger.warning(f"Admin blueprint initialization failed: {e}")
            
            try:
                from employee_dashboard_bp import init_employee_dashboard_db
                init_employee_dashboard_db(db)
                logger.info("✓ Employee dashboard blueprint database initialized")
            except Exception as e:
                logger.warning(f"Employee dashboard blueprint initialization failed: {e}")
            
            try:
                from mentor import init_mentor_db
                init_mentor_db(db)
                logger.info("✓ Mentor blueprint database initialized")
            except Exception as e:
                logger.warning(f"Mentor blueprint initialization failed: {e}")
            
            # Initialize SmartLoop after main tables
            try:
                from smartloop.models import Strategy, DailyLog
                db.create_all()
                logger.info("✓ SmartLoop database initialized")
            except Exception as e:
                logger.warning(f"SmartLoop initialization failed: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False

def main():
    """Main application startup"""
    try:
        # Set up environment
        setup_environment()
        
        # Import and create app
        logger.info("Importing application modules...")
        from app import app, db
        
        # Initialize database
        if not initialize_database(app, db):
            logger.error("Database initialization failed, exiting...")
            sys.exit(1)
        
        # Re-enable network calls for runtime
        os.environ.pop('SMARTAPI_DISABLE_NETWORK', None)
        
        # Start the application
        logger.info("Starting Flask application...")
        app.run(host="0.0.0.0", port=5000, debug=True)
        
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()