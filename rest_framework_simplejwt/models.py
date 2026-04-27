from typing import TYPE_CHECKING

from django.contrib.auth.models import Group, Permission
from django.utils.functional import cached_property

from .settings import api_settings


TYPE_CHECKING = TYPE_CHECKING  # Re-export for tests


class EmptyQuerySetProxy:
    """
    A proxy that mimics an empty QuerySet.
    """

    def exists(self):
        return False

    def all(self):
        return self

    def __iter__(self):
        return iter([])

    def __len__(self):
        return 0

    def __bool__(self):
        return False


class TokenUser:
    """
    A user class that is constructed from a JWT token payload instead of
    from a database lookup.
    """

    # Required by Django auth
    is_active = True

    _groups = EmptyQuerySetProxy()
    _user_permissions = EmptyQuerySetProxy()

    def __init__(self, token):
        self.token = token

    def __str__(self):
        return f"TokenUser {self.id}"

    def __repr__(self):
        return f"<TokenUser: {self.id}>"

    def __eq__(self, other):
        if not isinstance(other, TokenUser):
            return NotImplemented
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)

    @cached_property
    def id(self):
        return self.token.get(api_settings.USER_ID_CLAIM)

    @cached_property
    def pk(self):
        return self.id

    @cached_property
    def username(self):
        return self.token.get("username", "")

    @cached_property
    def is_staff(self):
        return self.token.get("is_staff", False)

    @cached_property
    def is_superuser(self):
        return self.token.get("is_superuser", False)

    def __getattr__(self, attr):
        """
        Allow access to any claim in the token via attribute access.
        """
        if attr.startswith("_"):
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{attr}'")
        return self.token.get(attr)

    def save(self):
        raise NotImplementedError("Token users cannot be saved to the database.")

    def delete(self):
        raise NotImplementedError("Token users cannot be deleted from the database.")

    def set_password(self, raw_password):
        raise NotImplementedError("Token users cannot have passwords set.")

    def check_password(self, raw_password):
        raise NotImplementedError("Token users cannot have passwords checked.")

    @property
    def groups(self):
        return self._groups

    @property
    def user_permissions(self):
        return self._user_permissions

    def get_group_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return set()

    def has_perm(self, perm, obj=None):
        return False

    def has_perms(self, perm_list, obj=None):
        return False

    def has_module_perms(self, module):
        return False

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    def get_username(self):
        return self.username
