from flask import request, g
from flask_restful import Resource
from marshmallow import ValidationError
from app.schemas.data_usage import DataUsageSchema  # Import DataUsageSchema
from app.utils.auth import token_required
from app.utils.database import get_db_connection, put_db_connection, execute_query
from app.utils.exceptions import APIException, DatabaseError


# Data Check Resource
class DataCheck(Resource):
    """
    API resource for logging user data usage.
    """
    @token_required
    def post(self):
        """
        Logs user data usage.
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

            if total_usage >= 1000:
                put_db_connection(conn)
                raise APIException("Bandwidth limit exceeded/reached, payment required to continue", 402)
            else:
                data_left = 1000 - total_usage

            return {"message": "Not reached limit", "data_left": data_left}, 200
        except ValidationError as err:
            return {"errors": err.messages}, 400
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error logging data usage: {e}")
            return {"message": "An error occurred while logging data usage"}, 500
        
#Data Usage Resource
class DataUsage(Resource):
    """
    API resource for logging user data usage.
    """

    @token_required
    def post(self):
        """
        Logs user data usage.
        """
        try:
            data = request.get_json()
            data_usage_schema = DataUsageSchema()
            validated_data = data_usage_schema.load(data)

            user_id = validated_data["user_id"]
            hotspot_id = validated_data["hotspot_id"]
            data_used = validated_data["data_used"]

            #check_data_usage_limit(user_id, hotspot_id, data_used)

            query = """
                INSERT INTO data_usage (user_id, hotspot_id, data_used, timestamp)
                VALUES (%s, %s, %s, NOW()) RETURNING usage_id
                """
            params = (user_id, hotspot_id, data_used)
            usage_id = execute_query(query, params, fetchone=True)[0]

            return {"message": "Data usage logged successfully", "usage_id": usage_id}, 200
        except ValidationError as err:
            return {"errors": err.messages}, 400
        except DatabaseError as e:
            return {"message": e.message}, 500
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            print(f"Error logging data usage: {e}")
            return {"message": "An error occurred while logging data usage"}, 500
