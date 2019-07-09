"""Schemas for Users service."""
from marshmallow import fields
from users_service import MA


class UserSchema(MA.Schema):  # pylint: disable=too-few-public-methods
    """Implementation of Users schema."""
    users_id = fields.Integer(dump_only=True)
    email = fields.Email()
    password = fields.Str()
    first_name = fields.Str()
    last_name = fields.Str()
    google_id = fields.Integer()
    create_date = fields.DateTime(dump_only=True)
    update_date = fields.DateTime(dump_only=True)
