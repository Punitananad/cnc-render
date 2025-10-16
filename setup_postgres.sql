-- PostgreSQL setup script
-- Run this in PostgreSQL command line or pgAdmin

-- Create database
CREATE DATABASE calculatentrade_db;

-- Create user
CREATE USER cnt_user WITH PASSWORD 'cnt_password_2024';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE calculatentrade_db TO cnt_user;

-- Connect to the database and grant schema privileges
\c calculatentrade_db;
GRANT ALL ON SCHEMA public TO cnt_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cnt_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cnt_user;