from marshmallow import Schema, fields, ValidationError, validate  # Import Marshmallow

class DataUsageSchema(Schema):
    """
    Schema for data usage logging.
    """
    user_id = fields.Integer(required=True, validate=validate.Range(min=1))
    hotspot_id = fields.Integer(required=True, validate=validate.Range(min=1))
    data_used = fields.Float(required=True, validate=validate.Range(min=0))