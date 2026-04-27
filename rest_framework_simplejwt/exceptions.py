from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed


class TokenError(Exception):
    """
    Base exception for all token-related errors.
    """
    pass


class ExpiredTokenError(TokenError):
    """
    Raised when a token has expired.
    """
    pass


class TokenBackendError(Exception):
    """
    Base exception for token backend errors.
    """
    pass


class TokenBackendExpiredToken(TokenBackendError):
    """
    Raised when the token backend detects an expired token.
    """
    pass


class InvalidToken(AuthenticationFailed):
    """
    Raised when an invalid token is encountered.
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _("Token is invalid or expired")
    default_code = "token_not_valid"


# Re-export AuthenticationFailed for convenience
AuthenticationFailed = AuthenticationFailed
