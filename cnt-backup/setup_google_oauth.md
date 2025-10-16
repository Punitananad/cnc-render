# Google OAuth Setup Instructions

## Step 1: Create Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:5000/auth/google/callback` (for development)
     - `https://yourdomain.com/auth/google/callback` (for production)

## Step 2: Update Environment Variables

Add these to your `.env` file:

```
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
```

Replace `your_google_client_id_here` and `your_google_client_secret_here` with the actual values from Google Cloud Console.

## Step 3: Install Required Packages

Run this command to install the required packages:

```bash
pip install authlib requests
```

## Step 4: Database Migration

The User model has been updated with new fields for Google OAuth. You may need to update your database:

- `google_id` - Stores the Google user ID
- `profile_pic` - Stores the profile picture URL
- `name` - Stores the full name from Google
- `password_hash` - Now nullable for OAuth users

## Step 5: Test the Integration

1. Start your Flask application
2. Go to the login or register page
3. Click "Continue with Google"
4. You should be redirected to Google for authentication
5. After successful authentication, you'll be redirected back to your app

## Features Added

- **Google Sign-in Button**: Added to both login and register pages
- **Automatic Account Creation**: New users are automatically created when they sign in with Google
- **Account Linking**: Existing users can link their Google account
- **Profile Information**: Name and profile picture are stored from Google
- **Email Verification**: Google accounts are automatically verified

## Security Notes

- Google OAuth users don't have passwords in your system
- All Google accounts are automatically marked as verified
- The integration handles both new user registration and existing user login
- Profile pictures and names are updated from Google on each login