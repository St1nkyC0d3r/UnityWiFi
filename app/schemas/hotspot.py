from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
from app.utils.validation import is_valid_bssid, is_security_type_valid, is_network_authentication_type_valid

class HotspotSchema(Schema):
    """
    Schema for hotspot registration.
    """
    # Hotspots
    ssid = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    bssid = fields.Str(required=True, validate=is_valid_bssid)
    max_signal_strength = fields.Integer(required=False, validate=validate.Range(min=1, max=100), allow_none=True, load_default=None)
    channel = fields.Integer(required=False, validate=validate.Range(min=1, max=14), allow_none=True, load_default=None)
    frequency = fields.Integer(required=False, allow_none=True, load_default=None)
    hotspot_details = fields.Str(required=False, allow_none=True, load_default=None)

    # user_id retreval
    username = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8))


    # location_id retrival
    latitude = fields.Float(required=True)
    longitude = fields.Float(required=True)
    altitude = fields.Integer(required=False, allow_none=True, load_default=None)
    address = fields.Str(required=False, validate=validate.Length(min=1,max=255), allow_none=True, load_default=None)
    city = fields.Str(required=False, validate=validate.Length(min=1,max=100), allow_none=True, load_default=None)
    country = fields.Str(required=False, validate=validate.Length(min=1,max=100), allow_none=True, load_default=None)
    postal_code = fields.Str(required=False, validate=validate.Length(min=1,max=20), allow_none=True, load_default=None)
    geometry = fields.Str(required=False, allow_none=True, load_default=None)                           #################################################################### AHAHA gonna sort this out soon (ish)

    # network_id retrival
    encryption_method = fields.Integer(required=True, validate=is_security_type_valid)
    authentication_method = fields.Str(required=True, validate=is_network_authentication_type_valid)
    qos_support = fields.Boolean(required=True)
    ipv4_address = fields.IPv4(required=True)
    ipv6_address = fields.IPv6(required=True)
    network_details = fields.Str(required=False, allow_none=True, load_default=None)
