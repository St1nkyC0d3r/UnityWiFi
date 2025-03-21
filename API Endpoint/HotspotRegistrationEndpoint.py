from flask import Flask, request, g
from flask_restful import Api, Resource
from psycopg2 import connect, extras, errors
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from jwt import encode, decode
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from typing import Tuple, Dict, Any
from urllib.parse import urlparse, parse_qs
from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
from flasgger import swag_from, Swagger # Import Swagger
import os
from common import error_response


# Load environment variables
load_dotenv()

app = Flask(__name__)
api = Api(app)
swagger = Swagger(app)

# Database connection details from environment variables
DB_HOST = os.environ.get("DB_HOST")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
JWT_ALGORITHM = 'HS256'
CONNECTION_POOL_SIZE = int(os.environ.get("CONNECTION_POOL_SIZE", 10))

# Configuration
app.config['CONNECTION_POOL_SIZE'] = CONNECTION_POOL_SIZE
app.config['JWT_ISSUER'] = 'unitywifi.com'
app.config['JWT_AUDIENCE'] = 'unitywifi.com'


# Initialize connection pool
def init_db_connection_pool():
    """
    Initializes the PostgreSQL connection pool.
    """
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
        return {"message": self.message, "code": self.status_code}

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
    ssid = fields.Str(required=True, validate=validate.Length(min=1, max=32))
    bssid = fields.Str(required=True, validate=validate.Regexp(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"))
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



def execute_query(query: str, params: tuple = None, fetchone: bool = False, commit: bool = True) -> Any:
    """
    Executes a database query and handles connection management.

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



# Hotspot Registration Resource
class HotspotRegister(Resource):
    """
    API resource for registering a new Wi-Fi hotspot.
    """

    @token_required
    @swag_from('docs/hotspot_register.yml')
    def post(self):
        """
        Registers a new Wi-Fi hotspot.

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

            validate_unique_bssid_ssid(ssid, bssid) # Check for uniqueness

            query = """
                INSERT INTO hotspots (ssid, bssid, location_id, network_id, provider_id)
                VALUES (%s, %s, %s, %s, %s) RETURNING hotspot_id
                """
            params = (ssid, bssid, location_id, network_id, provider_id)
            hotspot_id = execute_query(query, params, fetchone=True)["hotspot_id"]

            return {"message": "Hotspot registered successfully", "hotspot_id": hotspot_id}, 201
        except ValidationError as err:
            return error_response(err.messages, 400), 400
        except errors.UniqueViolation as e:
            return error_response("Hotspot with this BSSID and SSID already exists", 400), 400
        except DatabaseError as e:
            return error_response(e.message, 500), 500
        except APIException as e:
            return error_response(e.message, e.status_code), e.status_code
        except Exception as e:
            print(f"Error registering hotspot: {e}")
            return error_response("An error occurred during hotspot registration", 500), 500



# Add resources to the API
api.add_resource(HotspotRegister, "/hotspot/register")


@app.errorhandler(400)
def handle_bad_request(error):
    """
    Error handler for 400 Bad Request errors.
    """
    return error_response("Invalid request", 400), 400

@app.errorhandler(401)
def handle_unauthorized(error):
    """
    Error handler for 401 Unauthorized errors.
    """
    return error_response("Unauthorized", 401), 401

@app.errorhandler(500)
def handle_internal_server_error(error):
    """
    Error handler for 500 Internal Server Error errors.
    """
    return error_response("Internal server error", 500), 500



# Define Swagger definitions
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
                    "maxLength": 32,
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


if __name__ == "__main__":
    init_db_connection_pool()
    app.run(debug=True, host="0.0.0.0")
