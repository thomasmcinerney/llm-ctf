#!/usr/bin/env python3
import sqlite3
import sys
import os
from passlib.context import CryptContext

# Change to backend directory
os.chdir('backend')

# Initialize password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Connect to database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create tables if they don't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Delete existing lain user
cursor.execute('DELETE FROM users WHERE username = ?', ('lain',))
print(f"Deleted {cursor.rowcount} existing 'lain' user(s)")

# Create new lain user with password 'lain'
password_hash = pwd_context.hash('lain')
cursor.execute('''
INSERT INTO users (username, password_hash, is_admin)
VALUES (?, ?, ?)
''', ('lain', password_hash, False))

print("Created new 'lain' user with password 'lain'")

# Verify the user was created
cursor.execute('SELECT username, password_hash FROM users WHERE username = ?', ('lain',))
result = cursor.fetchone()
if result:
    print(f"User in DB: {result[0]}")
    # Test password verification
    if pwd_context.verify('lain', result[1]):
        print("✓ Password verification works!")
    else:
        print("✗ Password verification failed!")

conn.commit()
conn.close()
print("Database reset complete!")