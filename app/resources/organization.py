from flask import request, g
from flask_restful import Resource
from marshmallow import ValidationError
from app.schemas.organizations import OrganizationsSchema
from app.utils.auth import token_required
from app.utils.database import get_db_connection, put_db_connection
from app.utils.exceptions import APIException
from app.utils.auth import get_user_id


# Provider Register Resource
class ProviderRegister(Resource):
    """
    API Resource for registering providers
    """
    @token_required
    def post(self):
        """
        Registers providers.
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
            return {"errors": err.messages}, 400
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error registering hotspot: {e}")
            return {"message": "An error occurred during hotspot registration"}, 500
