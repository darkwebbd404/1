import jwt
import requests
import json
import time
from datetime import datetime

# Authentication related functions for Free Fire bot

def encrypt_api(payload):
    """Encrypt API payload using AES encryption"""
    try:
        from src.packet_builder import encrypt_packet, key, iv
        return encrypt_packet(payload, key, iv)
    except Exception as e:
        print(f"Error encrypting payload: {e}")
        return payload

def validate_token(token):
    """Validate JWT token"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return True, decoded
    except Exception as e:
        return False, str(e)

def refresh_token(old_token):
    """Refresh authentication token"""
    try:
        # Token refresh logic here
        return old_token
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return None

def get_auth_headers(token):
    """Get authentication headers for API requests"""
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'User-Agent': 'FreeFire-Bot/1.0'
    }
