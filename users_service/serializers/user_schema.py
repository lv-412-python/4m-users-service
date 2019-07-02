"""Schemas for Users service."""
from users_service import MA


class UserSchema(MA.Schema):  # pylint: disable=too-few-public-methods
    """Implementation of Users schema."""
    class Meta:  # pylint: disable=too-few-public-methods
        """Implementation of Meta class with fields, we want to show."""
        fields = ('users_id', 'email', 'first_name', 'last_name',
                  'google_id', 'password', 'admin', 'create_date', 'update_date')


USER_SCHEMA = UserSchema(strict=True)
USERS_SCHEMA = UserSchema(many=True, strict=True)
