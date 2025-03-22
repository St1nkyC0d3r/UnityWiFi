from flask import request, g
from flask_restful import Resource
from marshmallow import ValidationError
import bcrypt
from app.schemas.hotspot import HotspotSchema  # Import HotspotSchema
from app.utils.auth import generate_token, token_required
from app.utils.database import get_db_connection, put_db_connection
from app.utils.exceptions import APIException
from flasgger import swag_from


# Hotspot Registration Resource
class HotspotRegister(Resource):
    """
    API resource for registering a new Wi-Fi hotspot.
    """

    @token_required
    @swag_from('app/docs/hotspot_register.yml')
    def post(self):
        """
        Registers a new Wi-Fi hotspot.
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
            return {"errors": err.messages}, 400
        except APIException as e:
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error registering hotspot: {e}")
            return {"message": "An error occurred during hotspot registration"}, 500

# Hotspot Details Resource
class HotspotDetails(Resource):
    """
    API resource for retrieving hotspot details by ID.
    """
    @token_required
    @swag_from('app/docs/hotspot_details.yml')
    def get(self, hotspot_id: int):
        """
        Retrieves hotspot details by ID.
        """
        if not isinstance(hotspot_id, int) or hotspot_id <= 0:
            return {"message": "Invalid hotspot ID"}, 400
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
            return {"message": e.message}, e.status_code
        except Exception as e:
            conn = getattr(g, 'conn', None)
            if conn:
                put_db_connection(conn)
            print(f"Error retrieving hotspot details: {e}")
            return {"message": "An error occurred while retrieving hotspot details"}, 500
