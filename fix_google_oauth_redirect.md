# Fix Google OAuth Redirect URI Error

## Problem
Google OAuth returns 404 error: "The requested URL was not found on this server"

## Root Cause
The redirect URI in your Google Cloud Console doesn't match what your app is sending.

## Solution

### Step 1: Go to Google Cloud Console
1. Visit: https://console.cloud.google.com/
2. Select your project
3. Go to "APIs & Services" > "Credentials"

### Step 2: Edit OAuth 2.0 Client
1. Find your OAuth 2.0 client ID: `724916457805-p1eneu30qrtav3grgegiihf86j5n4uct.apps.googleusercontent.com`
2. Click the edit button (pencil icon)

### Step 3: Add Authorized Redirect URIs
Add these EXACT URIs:
```
http://localhost:5000/auth/google/callback
https://calculatentrade.com/auth/google/callback
```

### Step 4: Save Changes
Click "Save" button

## Alternative Quick Fix
If you can't access Google Cloud Console, create a new OAuth client:

1. Go to Google Cloud Console > APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth 2.0 Client ID"
3. Choose "Web application"
4. Add authorized redirect URIs:
   - `http://localhost:5000/auth/google/callback`
5. Download the JSON file and replace `client_secret.json`
6. Update your `.env` file with new client ID and secret

## Test After Fix
1. Restart your Flask app
2. Go to http://localhost:5000/login
3. Click "Continue with Google"
4. Should work without 404 error

The issue is in Google Cloud Console configuration, not your code!