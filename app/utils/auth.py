import os
from flask import Flask, request, g
from jwt import encode, decode
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any
from dotenv import load_dotenv
from app.utils.database import get_db_connection, put_db_connection

# Load environment variables
load_dotenv()

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
JWT_ALGORITHM = 'HS256'
# Configuration
JWT_ISSUER = 'unitywifi.com'
JWT_AUDIENCE = 'unitywifi.com'

# Function to generate JWT token
def generate_token(user_id: int) -> str:
    """
    Generates a JSON Web Token (JWT) for a given user ID.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    token = encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

# Function to decode JWT token
def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes a JWT token.
    """
    try:
        payload = decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get('iss') != JWT_ISSUER or payload.get('aud') != JWT_AUDIENCE:
            raise Exception("Invalid issuer or audience")
        return payload
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None

# Authentication decorator to protect routes
def token_required(f):
    """
    Decorator to protect routes that require a valid JWT token.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return {"message": "Token is missing"}, 401

        if not token.startswith("Bearer "):
            return {"message": "Invalid token format.  Should be 'Bearer <token>'"}, 401
        try:
            token = token.split(" ")[1]
        except IndexError:
            return {"message": "Invalid token format."}, 401

        payload = decode_token(token)
        if not payload:
            return {"message": "Invalid or expired token"}, 401

        g.user_id = payload["user_id"]
        return f(*args, **kwargs)

    return decorated

def get_user_id(email: str, password: str) -> int:
    """
    Gets the user ID for a given email and password.
    """
    conn, cursor = get_db_connection()
    cursor.execute("SELECT user_id FROM users WHERE email = %s AND password_hash = %s", (email, password))
    user_id = cursor.fetchone()["user_id"]
    put_db_connection(conn)
    return user_id