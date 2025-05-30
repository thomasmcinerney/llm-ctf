#!/usr/bin/env python3
import sqlite3
import os

os.chdir('backend')

# Check what databases exist
import glob
db_files = glob.glob('*.db')
print(f"Found database files: {db_files}")

# Connect to each database and check users table
for db_file in db_files:
    print(f"\n=== Checking {db_file} ===")
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if cursor.fetchone():
            print("Users table exists")
            # Get all users
            cursor.execute("SELECT user_id, username, password_hash FROM users")
            users = cursor.fetchall()
            print(f"Found {len(users)} users:")
            for user in users:
                print(f"  ID: {user[0]}, Username: {user[1]}, Hash: {user[2][:20]}...")
        else:
            print("No users table found")
        
        conn.close()
    except Exception as e:
        print(f"Error: {e}")