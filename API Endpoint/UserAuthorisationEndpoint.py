import os
from flask import Flask, request, g
from flask_restful import Api, Resource
from psycopg2 import connect, extras
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from jwt import encode, decode
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from typing import Tuple, Dict, Any
import bcrypt
from urllib.parse import urlparse, parse_qs
from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
<<<<<<< Updated upstream
from flasgger import Swagger, swag_from  # Import Swagger
from common import *
from validation import *

=======
from flasgger import Swagger  # Import Swagger
import os
from common import error_response, is_valid_url, is_valid_bssid
>>>>>>> Stashed changes

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

def execute_query(query: str, params: tuple = None, fetchone: bool = False, commit: bool = True) -> Any:
    """
    Executes a database query and handles connection management.

<<<<<<< Updated upstream
    Args:
        query (str): The SQL query to execute.
        params (tuple, optional): Parameters to pass to the query. Defaults to None.
        fetchone (bool, optional): Whether to fetch one result or all. Defaults to False.
        commit (bool, optional): Whether to commit the transaction. Defaults to True.

    Returns:
        Any: The result of the query (None, one row, or all rows).

    Raises:
        DatabaseError: If a database error occurs.
    """
    conn, cursor = get_db_connection()
    try:
        cursor.execute(query, params)
        if fetchone:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
        if commit:
            conn.commit()
        return result
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database error: {e}")
        raise DatabaseError() from e  # Preserve original exception as context
    finally:
        put_db_connection(conn)

def validate_unique_bssid_ssid(ssid, bssid):
    """
    Checks if a BSSID and SSID combination is unique in the database.

    Args:
        ssid (str): The SSID to check.
        bssid (str): The BSSID to check.

    Raises:
        APIException: If the BSSID and SSID combination is not unique.
    """
    conn, cursor = get_db_connection()
    try:
        cursor.execute(
            "SELECT 1 FROM hotspots WHERE bssid = %s AND ssid = %s",
            (bssid, ssid),
        )
        if cursor.fetchone():
            raise APIException("A hotspot with this BSSID and SSID combination already exists.", 400)
    finally:
        put_db_connection(conn)

def check_data_usage_limit(user_id: int, hotspot_id: int, data_used: float):
    """
    Checks if a user has exceeded the data usage limit for a hotspot.

    Args:
        user_id (int): The ID of the user.
        hotspot_id (int): The ID of the hotspot.
        data_used (float): The amount of data used in MB.

    Raises:
        APIException: If the user has exceeded the data usage limit.
    """
    # Define the data usage limit (e.g., 1000 MB)
    data_usage_limit = 1000.0

    conn, cursor = get_db_connection()
    cursor.execute("SELECT SUM(data_used) FROM data_usage WHERE user_id = %s AND timestamp >= %s", (user_id, one_month_ago_exactly()))
    current_usage = cursor.fetchone()
    put_db_connection(conn)

    if current_usage + data_used > data_usage_limit:
        raise APIException(f"Data usage limit ({data_usage_limit} MB) exceeded for user {user_id}", 400)

def get_user_id(email: str, password: str):
    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if user:
        if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            put_db_connection(conn)
            return user["user_id"]
        else:
            put_db_connection(conn)
            raise APIException("Invalid credentials", 401)
    else:
        put_db_connection(conn)
        raise APIException("Invalid credentials", 401)



=======

>>>>>>> Stashed changes



def is_security_type_valid(security_type: str) -> bool:
    """
    Checks if a given string is a valid security type.
    """
    return security_type in ["WEP", "WPA", "WPA2", "WPA3", "None"]

def is_valid_email(email: str) -> bool:
    """
    Checks if a given string is a valid email address.
    """
    return ("@" in email) and ('.' in email.split("@")[1])

def is_network_authentication_type_valid(authentication_type: str) -> bool:
    """
    Checks if a given string is a valid network authentication type.
    """
    return authentication_type in ["EAP-SIM", "EAP-AKA", "EAP-TLS", "EAP-TTLS", "PEAP", "LEAP", "EAP-FAST", "EAP-PSK", "EAP-PWD", "EAP-IKEv2", "EAP-GTC", "EAP-MD5", "EAP-MSCHAPv2", "EAP-TLS", "EAP-TTLS", "PEAP", "LEAP", "EAP-FAST", "EAP-PSK", "EAP-PWD", "EAP-IKEv2", "EAP-GTC", "EAP-MD5", "EAP-MSCHAPv2"]
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
    
class DatabaseError(Exception):
    """
    Custom exception class for handling database errors.
    """
    def __init__(self, message="A database error occurred"):
        super().__init__(message)
        self.message = message



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
    # Hotspots
    ssid = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    bssid = fields.Str(required=True, validate=is_valid_bssid)
<<<<<<< Updated upstream
    max_signal_strength = fields.Integer(required=False, validate=validate.Range(min=1, max=100))
    channel = fields.Integer(required=False, validate=validate.Range(min=1, max=14))
    frequency = fields.Integer(required=False)
    hotspot_details = fields.Str(required=False)

    # user_id retreval
    username = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8))


    # location_id retrival
    latitude = fields.Float(required=True)
    longitude = fields.Float(required=True)
    altitude = fields.Integer(required=False)
    address = fields.Str(required=False, validate=validate.Length(min=1,max=255))
    city = fields.Str(required=False, validate=validate.Length(min=1,max=100))
    country = fields.Str(required=False, validate=validate.Length(min=1,max=100))
    postal_code = fields.Str(required=False, validate=validate.Length(min=1,max=20))
    geometry = fields.Str(required=False)                           #################################################################### AHAHA gonna sort this out soon (ish)

    # network_id retrival
    encryption_method = fields.Integer(required=True, validate=is_security_type_valid)
    authentication_method = fields.Str(required=True, validate=is_network_authentication_type_valid)
    qos_support = fields.Boolean(required=True)
    ipv4_address = fields.IPv4(required=True)
    ipv6_address = fields.IPv6(required=True)
    network_details = fields.Str(required=False)
=======
    location_id = fields.Integer(required=True, validate=validate.Range(min=1))
    network_id = fields.Integer(required=True, validate=validate.Range(min=1))
    provider_id = fields.Integer(required=False, validate=validate.Range(min=1))
    security_type = fields.Integer(required=True, validate=is_security_type_valid)
    max_signal_strength = fields.Integer(required=False, validate=validate.Range(min=1, max=100))
    channel = fields.Integer(required=False, validate=validate.Range(min=1, max=14))
    frequency = fields.Integer(required=False)
    details = fields.Str(required=False)
>>>>>>> Stashed changes

class DataUsageSchema(Schema):
    """
    Schema for data usage logging.
    """
    user_id = fields.Integer(required=True, validate=validate.Range(min=1))
    hotspot_id = fields.Integer(required=True, validate=validate.Range(min=1))
    data_used = fields.Float(required=True, validate=validate.Range(min=0))

class OrganizationsSchema(Schema):
    """
    Schema for organization registration.
    """
    provider_name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
<<<<<<< Updated upstream
    email = fields.Email(required=True, validate=is_valid_email)
    password = fields.Str(required=True, validate=validate.Length(min=8))
=======
    contact_email = fields.Email(required=True, validate=is_valid_email)
>>>>>>> Stashed changes
    contact_phone = fields.Str(required=True, validate=validate.Length(min=1, max=20))
    website = fields.Str(required=False, validate=is_valid_url)
    details = fields.Str(required=False)

<<<<<<< Updated upstream
=======
class NetworksSchema(Schema):
    """
    Schema for network registration.
    """
    encryption_method = fields.Str(required=True, validate=is_security_type_valid)
    authentication_method = fields.Str(required=True, validate=is_network_authentication_type_valid)
    qos_support = fields.Boolean(required=False)
    ipv4_address = fields.IPv4(required=False)
    ipv6_address = fields.IPv6(required=False)
    details = fields.Str(required=False)

>>>>>>> Stashed changes
class LocationsSchema(Schema):
    """
    Schema for location registration.
    """
    latitude = fields.Float(required=True)
    longitude = fields.Float(required=True)
    altitude = fields.Float(required=False)
    address = fields.Str(required=False, validate=validate.Length(min=1, max=255))
    city = fields.Str(required=False, validate=validate.Length(min=1, max=100))
    country = fields.Str(required=False, validate=validate.Length(min=1, max=100))
    postal_code = fields.Str(required=False, validate=validate.Length(min=1, max=20))
    geometry = fields.Str(required=False)
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes


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

            cursor.execute("INSERT INTO users (username, email, password_hash, registration_date) VALUES (%s, %s, %s, NOW()) RETURNING user_id", (username, email, hashed_password))
            user_id = cursor.fetchone()["user_id"]
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
<<<<<<< Updated upstream
                    token = generate_token(user["user_id"])
=======
                    token = generate_token(user["id"])
>>>>>>> Stashed changes
                    cursor.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user["user_id"],))
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
            # Fetch ssid, bssid etc
            ssid = validated_data["ssid"]
            bssid = validated_data["bssid"]
            max_signal_strength = validated_data["max_signal_strenth"]
            channel = validated_data["channel"]
            frequency = validated_data["frequency"]
            hotspot_details = validated_data["hotspot_details"]

            latitude = validated_data["latitude"]
            longitude = validated_data["longitude"]
            altitude = validated_data["altitude"]
            address = validated_data["address"]
            city = validated_data["city"]
            country = validated_data["country"]
            postal_code = validated_data["postal_code"]
            geometry = validated_data["geometry"]

            username = validated_data["username"]
            password = validated_data["password"]

            encryption_method = validated_data["encryption_method"]
            authentication_method = validated_data["authentication_method"]
            qos_support = validated_data["qos_support"]
            ipv4_address = validated_data["ipv4_address"]
            ipv6_address = validated_data["ipv6_address"]
            network_details = validated_data["network_details"]

            validate_unique_bssid_ssid(ssid, bssid) # Check for uniqueness


            # Check valid user.
            conn, cursor = get_db_connection()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                    cursor.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user["user_id"],))
                    conn.commit()
                    put_db_connection(conn)
                    conn, cursor = get_db_connection()
                    cursor.execute("SELECT provider_id FROM organizations WHERE user_id = %s", (user["user_id"],))
                    existing_provider = cursor.fetchone()
                    if existing_provider:
                        provider_id = existing_provider["provider_id"]
                        conn, cursor = get_db_connection()
                        cursor.execute("INSERT INTO locations (latitude, longitude, altitude, address, city, country, postal_code, geometry) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING location_id", (longitude, latitude, altitude, address, city, country, postal_code, geometry,))
                        location = cursor.fetchone()
                        put_db_connection(conn)
                        location_id = location["location_id"]
                        conn, cursor = get_db_connection()
                        cursor.execute("INSERT INTO networks (encryption_method, authentication_method, qos_support, ipv4_address, ipv6_address, details) VALUES (%s, %s, %s, %s, %s, %s) RETURNING network_id", (encryption_method, authentication_method, qos_support, ipv4_address, ipv6_address, network_details))
                        network_id = cursor.fetchone()["network_id"]
                        conn, cursor = get_db_connection()
                        cursor.execute(
                            """
                            INSERT INTO hotspots (network_id, location_id, provider_id, ssid, bssid, max_signal_strength, channel, frequency, details)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING hotspot_id
                            """,
                            (network_id, location_id, provider_id, ssid, bssid, max_signal_strength, channel, frequency, hotspot_details),
                        )
                        hotspot_id = cursor.fetchone()["hotspot_id"]
                        conn.commit()
                        put_db_connection(conn)
                        return {"message": "Hotspot registered successfully", "hotspot_id": hotspot_id}, 201
                    else:
                        put_db_connection(conn)
                        raise APIException("Not registered to be an organization.", 401)
                else:
                    put_db_connection(conn)
                    raise APIException("Invalid username/password", 401)
            else:
                put_db_connection(conn)
                raise APIException("Invalid username/password", 401)

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

# Data Check Resource
class DataCheck(Resource):
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

            if total_usage >= BANDWIDTH_LIMIT:
                put_db_connection(conn)
                raise APIException("Bandwidth limit exceeded/reached, payment required to continue", 402)
            else:
                data_left = BANDWIDTH_LIMIT - total_usage

            return {"message": "Not reached limit", "data_left": data_left}, 201
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
        
#Data Usage Resource
class DataUsage(Resource):
    """
    API resource for logging user data usage.
    """

    @token_required
    @swag_from('docs/data_usage.yml')
    def post(self):
        """
        Logs user data usage.

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
          200:
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

            check_data_usage_limit(user_id, hotspot_id, data_used)

            query = """
                INSERT INTO data_usage (user_id, hotspot_id, data_used, timestamp)
                VALUES (%s, %s, %s, NOW()) RETURNING usage_id
                """
            params = (user_id, hotspot_id, data_used)
            usage_id = execute_query(query, params, fetchone=True)[0]

            return {"message": "Data usage logged successfully", "usage_id": usage_id}, 200
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except DatabaseError as e:
            return error_response(e.message, 500), 500
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            print(f"Error logging data usage: {e}")
            return error_response("An error occurred while logging data usage", 500), 500

# Provider Register Resource
class ProviderRegister(Resource):
    """
    API Resource for registering providers
    """
    def post(self):
        """
        Registers providers.

        tags:
          - Provider Registration
        security:
          - BearerAuth: []
        parameters:
          - in: body
            name: body
            description: Registration to become a Provider.
            required: true
            schema:
              $ref: '#/definitions/OrganizationsSchema'
        responses:
          200:
            description: Provider registered successfully.
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
            organization_schema = OrganizationsSchema()
            validated_data = organization_schema.load(data)

            provider_name = validated_data["provider_name"]
            email = validated_data["email"]
            password = validated_data["password"]
            contact_phone = validated_data["contact_phone"]
            website = validated_data["website"]
            details = validated_data["details"]
            user_id = get_user_id(email, password)

            conn, cursor = get_db_connection()
            cursor.execute("SELECT provider_id FROM organizations WHERE user_id = %s", (user_id,))
            existing_provider = cursor.fetchone()
            if existing_provider:
                put_db_connection(conn)
                raise APIException("User already registered as provider", 401)
            else: 
                cursor.execute("INSERT INTO organizations (provider_name, user_id, contact_phone, website, details) VALUES (%s, %s, %s, %s, %s) RETURNING provider_id", (provider_name, user_id, contact_phone, website, details))
                provider_id = cursor.fetchone()["provider_id"]
                conn.commit()
                put_db_connection(conn)

                return {"message": "Provider registered successfully.", "provider_id": provider_id}, 200

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

# Provider Funds Resource



# Add resources to the API
api.add_resource(UserRegister, "/register")
api.add_resource(UserLogin, "/login")
api.add_resource(HotspotRegister, "/hotspot/register")
api.add_resource(HotspotDetails, "/hotspot/<int:hotspot_id>")
api.add_resource(DataCheck, "/data_check")
api.add_resource(DataUsage, "/data_usage")
api.add_resource(ProviderRegister, "/provider/register")



if __name__ == "__main__":
    init_db_connection_pool()
    app.run(debug=True, host="0.0.0.0")
