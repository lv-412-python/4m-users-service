"""Schemas for Users service."""
from marshmallow import fields
from users_service import MA


class RoleSchema(MA.Schema):  # pylint: disable=too-few-public-methods
    """Implementation of Roles schema."""
    id = fields.Integer(dump_only=True)
    role_name = fields.Str()
    role_description = fields.Str()


class UserSchema(MA.Schema):  # pylint: disable=too-few-public-methods
    """Implementation of Users schema."""
    user_id = fields.Integer(dump_only=True)
    email = fields.Email()
    first_name = fields.Str()
    last_name = fields.Str()
    password = fields.Str()
    google_id = fields.Integer()
    role = fields.Nested(RoleSchema)
    create_date = fields.DateTime(dump_only=True)
    update_date = fields.DateTime(dump_only=True)
