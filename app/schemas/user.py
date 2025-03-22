from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow

class UserSchema(Schema):
    """
    Schema for user registration and login.
    """
    username = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    email = fields.Email(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8))
    old_password = fields.Str(required=False, validate=validate.Length(min=8), allow_none=True, load_default=None)
    new_password = fields.Str(required=False, validate=validate.Length(min=8), allow_none=True, load_default=None)