from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow
from app.utils.validation import is_valid_email, is_valid_url

class OrganizationsSchema(Schema):
    """
    Schema for organization registration.
    """
    provider_name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    email = fields.Email(required=True, validate=is_valid_email)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    contact_phone = fields.Str(required=True, validate=validate.Length(min=1, max=20))
    website = fields.Str(required=False, validate=is_valid_url, allow_none=True, load_default=None)
    details = fields.Str(required=False, allow_none=True, load_default=None)