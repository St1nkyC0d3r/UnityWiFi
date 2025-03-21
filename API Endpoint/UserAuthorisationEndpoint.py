import os
from flask import Flask, request, g
from flask_restful import Api, Resource
from psycopg2 import connect, extras
from psycopg2.pool import ThreadedConnectionPool
from jwt import encode, decode
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from typing import Tuple, Dict, Any
import bcrypt
from urllib.parse import urlparse, parse_qs
from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
from flasgger import Swagger  # Import Swagger
import os
from common import error_response

# Load environment variables
load_dotenv()

app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)

swagger_config = {
    "swagger": "2.0",
    "info": {
        "title": "UnityWiFi API",
        "description": "API for managing users, hotspots, and data usage for the UnityWiFi platform.",
        "version": "1.0.0",
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Bearer token required, e.g., 'Bearer eyJhbGci...'",
        },
    },
    "definitions": {
        "UserSchema": {
            "type": "object",
            "required": ["username", "email", "password"],
            "properties": {
                "username": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": "User's username."
                },
                "email": {
                    "type": "string",
                    "format": "email",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": "User's email address."
                },
                "password": {
                    "type": "string",
                    "minLength": 8,
                    "description": "User's password (minimum 8 characters)."
                },
            },
        },
        "HotspotSchema": {
            "type": "object",
            "required": ["ssid", "bssid", "location_id", "network_id"],
            "properties": {
                "ssid": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 255,
                    "description": "SSID of the hotspot."
                },
                "bssid": {
                    "type": "string",
                    "pattern": "^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$",
                    "description": "BSSID of the hotspot (MAC address)."
                },
                "location_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "ID of the location."
                },
                "network_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "ID of the network."
                },
                 "provider_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "ID of the provider (organization).",
                    "nullable": True
                },
            },
        },
        "DataUsageSchema": {
            "type": "object",
            "required": ["user_id", "hotspot_id", "data_used"],
            "properties": {
                "user_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "ID of the user."
                },
                "hotspot_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "ID of the hotspot."
                },
                "data_used": {
                    "type": "number",
                    "format": "float",
                    "minimum": 0,
                    "description": "Data used in MB."
                },
            },
        },
        "ErrorResponse": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Error message."
                        },
                        "code": {
                            "type": "integer",
                            "description": "HTTP status code."
                        }
                    },
                    "required": ["message", "code"]
                }
            },
            "required": ["error"]
        }
    }
}


# Database connection details from environment variables
DB_HOST = os.environ.get("DB_HOST")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
JWT_ALGORITHM = 'HS256'
CONNECTION_POOL_SIZE = int(os.environ.get("CONNECTION_POOL_SIZE", 10))
BANDWIDTH_LIMIT = 1000  # MB per month (example)
EARNINGS_RATE = 0.01  # $ per MB (example)

# Configuration
app.config['CONNECTION_POOL_SIZE'] = CONNECTION_POOL_SIZE
app.config['JWT_ISSUER'] = 'unitywifi.com'
app.config['JWT_AUDIENCE'] = 'unitywifi.com'


# Initialize connection pool
def init_db_connection_pool():
    """Initializes the PostgreSQL connection pool."""
    try:
        app.pool = ThreadedConnectionPool(
            minconn=2,
            maxconn=app.config['CONNECTION_POOL_SIZE'],
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        print("Connection pool initialized successfully.")
    except Exception as e:
        print(f"Error initializing connection pool: {e}")
        raise

# Get connection from the pool
def get_db_connection() -> Tuple[connect, extras.DictCursor]:
    """
    Retrieves a connection from the connection pool and returns the connection and cursor.
    """
    try:
        conn = app.pool.getconn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        return conn, cursor
    except Exception as e:
        print(f"Error getting connection from pool: {e}")
        raise

# Put connection back to the pool
def put_db_connection(conn: connect):
    """
    Puts a connection back into the connection pool.
    """
    if conn:
        app.pool.putconn(conn)

# Function to generate JWT token
def generate_token(user_id: int) -> str:
    """
    Generates a JSON Web Token (JWT) for a given user ID.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow(),
        "iss": app.config['JWT_ISSUER'],
        "aud": app.config['JWT_AUDIENCE'],
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
        if payload.get('iss') != app.config['JWT_ISSUER'] or payload.get('aud') != app.config['JWT_AUDIENCE']:
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
            return error_response("Token is missing", 401), 401

        if not token.startswith("Bearer "):
            return error_response("Invalid token format.  Should be 'Bearer <token>'", 401), 401
        try:
            token = token.split(" ")[1]
        except IndexError:
            return error_response("Invalid token format.", 401), 401

        payload = decode_token(token)
        if not payload:
            return error_response("Invalid or expired token", 401), 401

        g.user_id = payload["user_id"]
        return f(*args, **kwargs)

    return decorated


def is_valid_url(url: str) -> bool:
    """
    Checks if a given string is a valid URL.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_valid_bssid(bssid: str) -> bool:
    """
    Checks if a given string is a valid BSSID.
    """
    if not isinstance(bssid, str):
        return False
    parts = bssid.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        try:
            int(part, 16)
        except ValueError:
            return False
        if len(part) != 2:
            return False
    return True

# Custom Exception for handling errors
class APIException(Exception):
    """
    Custom exception class for handling API errors.
    """
    def __init__(self, message, status_code):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_dict(self):
        return {"message": self.message}


# Schema Definitions (Marshmallow)
class UserSchema(Schema):
    """
    Schema for user registration and login.
    """
    username = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    email = fields.Email(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8))


class HotspotSchema(Schema):
    """
    Schema for hotspot registration.
    """
    ssid = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    bssid = fields.Str(required=True, validate=is_valid_bssid)
    location_id = fields.Integer(required=True, validate=validate.Range(min=1))
    network_id = fields.Integer(required=True, validate=validate.Range(min=1))
    provider_id = fields.Integer(required=False, validate=validate.Range(min=1))


class DataUsageSchema(Schema):
    """
    Schema for data usage logging.
    """
    user_id = fields.Integer(required=True, validate=validate.Range(min=1))
    hotspot_id = fields.Integer(required=True, validate=validate.Range(min=1))
    data_used = fields.Float(required=True, validate=validate.Range(min=0))



# User Registration Resource
class UserRegister(Resource):
    """
    API resource for user registration.
    """
    def post(self):
        """
        Handles user registration.
        ---
        tags:
          - User
        parameters:
          - in: body
            name: body
            description: User registration details.
            required: true
            schema:
              $ref: '#/definitions/UserSchema'
        responses:
          201:
            description: User registered successfully.
            schema:
              type: object
              properties:
                message:
                  type: string
                token:
                  type: string
          400:
            description: Bad request.
            schema:
              $ref: '#/definitions/ErrorResponse'
          500:
            description: Internal server error.
            schema:
              $ref: '#/definitions/ErrorResponse'
        """
        try:
            data = request.get_json()
            user_schema = UserSchema()
            validated_data = user_schema.load(data)  # Use Marshmallow for validation

            username = validated_data["username"]
            email = validated_data["email"]
            password = validated_data["password"]

            conn, cursor = get_db_connection()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user_username = cursor.fetchone()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user_email = cursor.fetchone()

            if existing_user_username:
                put_db_connection(conn)
                raise APIException("Username already exists", 400)
            if existing_user_email:
                put_db_connection(conn)
                raise APIException("Email already exists", 400)

            hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            cursor.execute("INSERT INTO users (username, email, password_hash, registration_date) VALUES (%s, %s, %s, NOW()) RETURNING id", (username, email, hashed_password))
            user_id = cursor.fetchone()["id"]
            conn.commit()
            put_db_connection(conn)

            token = generate_token(user_id)
            return {"message": "User registered successfully", "token": token}, 201
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error registering user: {e}")
            return error_response("An error occurred during registration", 500), 500



# User Login Resource
class UserLogin(Resource):
    """
    API resource for user login.
    """

    def post(self):
        """
        Handles user login.
        ---
        tags:
          - User
        parameters:
          - in: body
            name: body
            description: User login details.
            required: true
            schema:
              $ref: '#/definitions/UserSchema'
        responses:
          200:
            description: User logged in successfully.
            schema:
              type: object
              properties:
                message:
                  type: string
                token:
                  type: string
          401:
            description: Invalid credentials.
            schema:
              $ref: '#/definitions/ErrorResponse'
          500:
            description: Internal server error.
            schema:
              $ref: '#/definitions/ErrorResponse'
        """
        try:
            data = request.get_json()
            user_schema = UserSchema()
            validated_data = user_schema.load(data, partial=('email',))  #partial validation
            username = validated_data["username"]
            password = validated_data["password"]

            conn, cursor = get_db_connection()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                    token = generate_token(user["id"])
                    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user["id"],))
                    conn.commit()
                    put_db_connection(conn)
                    return {"message": "User logged in successfully", "token": token}, 200
                else:
                    put_db_connection(conn)
                    raise APIException("Invalid credentials", 401)
            else:
                put_db_connection(conn)
                raise APIException("Invalid credentials", 401)
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error logging in: {e}")
            return error_response("An error occurred during login", 500), 500


# Hotspot Registration Resource
class HotspotRegister(Resource):
    """
    API resource for registering a new Wi-Fi hotspot.
    """

    @token_required
    def post(self):
        """
        Registers a new Wi-Fi hotspot.
        ---
        tags:
          - Hotspot
        security:
          - BearerAuth: []
        parameters:
          - in: body
            name: body
            description: Hotspot registration details.
            required: true
            schema:
              $ref: '#/definitions/HotspotSchema'
        responses:
          201:
            description: Hotspot registered successfully.
            schema:
              type: object
              properties:
                message:
                  type: string
                hotspot_id:
                  type: integer
          400:
            description: Bad request.
            schema:
              $ref: '#/definitions/ErrorResponse'
          401:
            description: Unauthorized.
            schema:
              $ref: '#/definitions/ErrorResponse'
          500:
            description: Internal server error.
            schema:
              $ref: '#/definitions/ErrorResponse'
        """
        try:
            data = request.get_json()
            hotspot_schema = HotspotSchema()
            validated_data = hotspot_schema.load(data)

            ssid = validated_data["ssid"]
            bssid = validated_data["bssid"]
            location_id = validated_data["location_id"]
            network_id = validated_data["network_id"]
            provider_id = validated_data.get("provider_id")

            conn, cursor = get_db_connection()
            cursor.execute(
                """
                INSERT INTO hotspots (ssid, bssid, location_id, network_id, provider_id)
                VALUES (%s, %s, %s, %s, %s) RETURNING hotspot_id
                """,
                (ssid, bssid, location_id, network_id, provider_id),
            )
            hotspot_id = cursor.fetchone()["hotspot_id"]
            conn.commit()
            put_db_connection(conn)
            return {"message": "Hotspot registered successfully", "hotspot_id": hotspot_id}, 201
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error registering hotspot: {e}")
            return error_response("An error occurred during hotspot registration", 500), 500


# Hotspot Details Resource
class HotspotDetails(Resource):
    """
    API resource for retrieving hotspot details by ID.
    """
    @token_required
    def get(self, hotspot_id: int):
        """
        Retrieves hotspot details by ID.
        ---
        tags:
          - Hotspot
        security:
          - BearerAuth: []
        parameters:
          - name: hotspot_id
            in: path
            type: integer
            required: true
            description: The ID of the hotspot to retrieve.
        responses:
          200:
            description: Hotspot details retrieved successfully.
            schema:
              type: object
              properties:
                hotspot:
                  type: object
                  # Define the structure of the hotspot object here
          400:
            description: Bad request.
            schema:
              $ref: '#/definitions/ErrorResponse'
          401:
            description: Unauthorized.
            schema:
              $ref: '#/definitions/ErrorResponse'
          404:
            description: Hotspot not found.
            schema:
              $ref: '#/definitions/ErrorResponse'
          500:
            description: Internal server error.
            schema:
              $ref: '#/definitions/ErrorResponse'
        """
        if not isinstance(hotspot_id, int) or hotspot_id <= 0:
            return error_response("Invalid hotspot ID", 400), 400
        try:
            conn, cursor = get_db_connection()
            cursor.execute("SELECT * FROM hotspots WHERE hotspot_id = %s", (hotspot_id,))
            hotspot = cursor.fetchone()
            put_db_connection(conn)

            if hotspot:
                return {"hotspot": hotspot}, 200
            else:
                raise APIException("Hotspot not found", 404)
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error retrieving hotspot details: {e}")
            return error_response("An error occurred while retrieving hotspot details", 500), 500



# Data Usage Resource
class DataUsage(Resource):
    """
    API resource for logging user data usage.
    """
    @token_required
    def post(self):
        """
        Logs user data usage.
        ---
        tags:
          - Data Usage
        security:
          - BearerAuth: []
        parameters:
          - in: body
            name: body
            description: Data usage details.
            required: true
            schema:
              $ref: '#/definitions/DataUsageSchema'
        responses:
          201:
            description: Data usage logged successfully.
            schema:
              type: object
              properties:
                message:
                  type: string
          400:
            description: Bad request.
            schema:
              $ref: '#/definitions/ErrorResponse'
          401:
            description: Unauthorized.
            schema:
              $ref: '#/definitions/ErrorResponse'
          500:
            description: Internal server error.
            schema:
              $ref: '#/definitions/ErrorResponse'
        """
        try:
            data = request.get_json()
            data_usage_schema = DataUsageSchema()
            validated_data = data_usage_schema.load(data)

            user_id = validated_data["user_id"]
            hotspot_id = validated_data["hotspot_id"]
            data_used = validated_data["data_used"]

            conn, cursor = get_db_connection()
            cursor.execute(
                """
                SELECT SUM(data_used) as total_usage
                FROM data_usage
                WHERE user_id = %s AND hotspot_id = %s
                AND timestamp >= NOW() - INTERVAL '1 month'
                """,
                (user_id, hotspot_id),
            )
            result = cursor.fetchone()
            total_usage = result["total_usage"] if result["total_usage"] else 0

            if total_usage + data_used > BANDWIDTH_LIMIT:
                put_db_connection(conn)
                raise APIException("Bandwidth limit exceeded", 400)

            cursor.execute(
                "INSERT INTO data_usage (user_id, hotspot_id, data_used, timestamp) VALUES (%s, %s, %s, NOW())",
                (user_id, hotspot_id, data_used),
            )

            # Calculate earnings for the business (Example)
            cursor.execute(
                "SELECT business_id FROM hotspots WHERE hotspot_id = %s",
                (hotspot_id,)
            )
            business_id_result = cursor.fetchone()
            if business_id_result and business_id_result["business_id"]:
                business_id = business_id_result["business_id"]
                earnings = data_used * EARNINGS_RATE
                # In a real application, you would likely have an 'earnings' table
                # and update it accordingly.  This is a simplified example.
                print(f"Credited ${earnings} to business {business_id} for data usage.")

            conn.commit()
            put_db_connection(conn)
            return {"message": "Data usage logged successfully"}, 201
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error logging data usage: {e}")
            return error_response("An error occurred while logging data usage", 500), 500



# Add resources to the API
api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(HotspotRegister, "/hotspot/register")
api.add_resource(HotspotDetails, "/hotspot/<int:hotspot_id>")
api.add_resource(DataUsage, "/data_usage")




if __name__ == "__main__":
    init_db_connection_pool()
    app.run(debug=True, host="0.0.0.0")
