from flask import request, g
from flask_restful import Resource
from marshmallow import ValidationError
import bcrypt
from app.schemas.user import UserSchema  # Import UserSchema
from app.utils.auth import generate_token
from app.utils.database import get_db_connection, put_db_connection
from app.utils.exceptions import APIException
from flasgger import swag_from


# User Registration Resource
class UserRegister(Resource):
    """
    API resource for user registration.
    """
    @swag_from('app/docs/user_register.yml')
    def post(self):
        """
        Handles user registration.
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
            return {"errors": err.messages}, 400
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error registering user: {e}")
            return {"message": "An error occurred during registration"}, 500

# User Login Resource
class UserLogin(Resource):
    """
    API resource for user login.
    """
    @swag_from('app/docs/user_login.yml')
    def post(self):
        """
        Handles user login.
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
                    token = generate_token(user["user_id"])
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
            return {"errors": err.messages}, 400
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error logging in: {e}")
            return {"message": "An error occurred during login"}, 500
