# CalculatenTrade Application Startup Instructions

## Quick Start

### Option 1: Using the Batch File (Recommended for Windows)
1. Double-click `start_app.bat`
2. The application will start automatically with proper error handling

### Option 2: Using Python Script
1. Open Command Prompt or PowerShell
2. Navigate to the CNT directory
3. Run: `python run_app.py`

### Option 3: Direct App Execution (Not Recommended)
1. Run: `python app.py`
2. Note: This may cause database initialization issues

## Troubleshooting

### Common Issues and Solutions

#### 1. Foreign Key Error (smartloop_strategies.user_id)
**Error**: `Foreign key associated with column 'smartloop_strategies.user_id' could not find table 'user'`

**Solution**: Use `run_app.py` or `start_app.bat` instead of running `app.py` directly. These scripts ensure proper database initialization order.

#### 2. SmartApi Network Error
**Error**: Network timeout or connection errors during import

**Solution**: The application now automatically disables network calls during import. If you still see this error, ensure you're using the proper startup scripts.

#### 3. Timezone Error (pytz)
**Error**: `KeyboardInterrupt` during timezone initialization

**Solution**: The application now has fallback timezone handling. If IST fails, it will use UTC.

#### 4. Blueprint Registration Errors
**Error**: Various blueprint initialization errors

**Solution**: The startup scripts ensure blueprints are registered in the correct order after main database tables are created.

## Database Initialization Order

The application now follows this initialization sequence:

1. **Main Database Tables**: User, trades, settings, etc.
2. **Admin Blueprint**: Admin-specific tables
3. **Employee Dashboard**: Employee-specific tables  
4. **Mentor Blueprint**: Mentor-specific tables
5. **SmartLoop Blueprint**: Strategy and daily log tables

## Environment Variables

The following environment variables are automatically set by the startup scripts:

- `SMARTAPI_DISABLE_NETWORK=1`: Prevents network calls during import
- `OAUTHLIB_INSECURE_TRANSPORT=1`: Allows HTTP for development
- `FLASK_ENV=development`: Sets Flask to development mode

## Files Created for Error Handling

- `run_app.py`: Main startup script with proper error handling
- `start_app.bat`: Windows batch file for easy startup
- `smartapi_wrapper.py`: Wrapper to handle SmartApi import issues
- `test_db_init.py`: Test script to verify database initialization

## Development Notes

- Always use `run_app.py` for development to ensure proper initialization
- The application will create SQLite databases in the `instance/` directory
- All blueprint databases are initialized after the main database
- Network calls are disabled during import and re-enabled at runtime

## Support

If you continue to experience issues:

1. Check that all required packages are installed: `pip install -r requirements.txt`
2. Ensure Python 3.8+ is installed
3. Try deleting the `instance/` directory and restarting
4. Check the console output for specific error messages