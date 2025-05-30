#!/usr/bin/env python3
import sys
sys.path.append('backend')
from database import Database
from passlib.context import CryptContext

# Initialize
db = Database('backend/database.db')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Check user
user = db.get_user_by_username('lain')
if user:
    print(f"User found: {user['username']}")
    print(f"Password hash: {user['password_hash']}")
    
    # Test password verification
    test_passwords = ['lain', 'admin', 'password', '123456']
    for pwd in test_passwords:
        if pwd_context.verify(pwd, user['password_hash']):
            print(f"✓ Password is: '{pwd}'")
            break
    else:
        print("✗ None of the common passwords work")
        # Try to create a new hash for 'lain'
        new_hash = pwd_context.hash('lain')
        print(f"Expected hash for 'lain': {new_hash}")
else:
    print("User 'lain' not found")