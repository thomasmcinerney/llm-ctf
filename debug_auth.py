#!/usr/bin/env python3
"""
Debug script to test authentication flow
"""
import requests
import json

API_BASE = 'http://localhost:9000/api'

def test_auth_flow():
    print("=== Testing Authentication Flow ===\n")
    
    # Test 1: Try to access challenges without authentication
    print("1. Testing challenges endpoint without auth...")
    try:
        response = requests.get(f'{API_BASE}/challenges')
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 2: Login and get token
    print("2. Testing login...")
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    try:
        login_data = {"username": username, "password": password}
        response = requests.post(f'{API_BASE}/login_json', 
                               headers={'Content-Type': 'application/json'},
                               json=login_data)
        print(f"Login Status: {response.status_code}")
        print(f"Login Response: {response.text}")
        
        if response.status_code == 200:
            token_data = response.json()
            token = token_data['access_token']
            print(f"Got token: {token[:50]}...")
            
            # Test 3: Use token to access challenges
            print("\n3. Testing challenges endpoint with auth...")
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f'{API_BASE}/challenges', headers=headers)
            print(f"Challenges Status: {response.status_code}")
            print(f"Challenges Response: {response.text}")
            
        else:
            print("Login failed!")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_auth_flow()