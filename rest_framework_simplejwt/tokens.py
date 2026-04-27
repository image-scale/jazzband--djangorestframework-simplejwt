from datetime import timedelta
from typing import TYPE_CHECKING, Any, Dict, Optional
from uuid import uuid4

from django.apps import apps
from django.conf import settings

from .exceptions import ExpiredTokenError, TokenBackendError, TokenError
from .settings import api_settings
from .state import token_backend
from .utils import aware_utcnow, datetime_from_epoch, datetime_to_epoch, get_md5_hash_password


class Token:
    """
    Base class for all tokens.
    """

    token_type: Optional[str] = None
    lifetime: Optional[timedelta] = None

    def __init__(self, token=None, verify=True):
        """
        Create a new token with optional token string to decode.
        """
        if self.token_type is None or self.lifetime is None:
            raise TokenError(
                "Cannot create token with no type or lifetime"
            )

        self.token = token
        self.current_time = aware_utcnow()
        self.token_backend = self.get_token_backend()

        if token is not None:
            # Decode the token
            try:
                self.payload = self.token_backend.decode(token, verify=verify)
            except TokenBackendError:
                raise TokenError("Token is invalid or expired")

            if verify:
                self.verify()
        else:
            # Create a new token
            self.payload = {}
            self.set_exp(from_time=self.current_time, lifetime=self.lifetime)
            self.set_iat(at_time=self.current_time)
            self.set_jti()

            if api_settings.TOKEN_TYPE_CLAIM is not None:
                self.payload[api_settings.TOKEN_TYPE_CLAIM] = self.token_type

    def __repr__(self):
        return repr(self.payload)

    def __getitem__(self, key):
        return self.payload[key]

    def __setitem__(self, key, value):
        self.payload[key] = value

    def __delitem__(self, key):
        del self.payload[key]

    def __contains__(self, key):
        return key in self.payload

    def get(self, key, default=None):
        return self.payload.get(key, default)

    def __str__(self):
        """
        Signs and returns a token as a string.
        """
        return self.token_backend.encode(self.payload)

    def verify(self):
        """
        Performs additional validation steps beyond those carried out by the
        token backend.
        """
        self.check_exp()

        # Ensure token type claim is present
        if api_settings.TOKEN_TYPE_CLAIM is not None:
            self.verify_token_type()

        # Ensure JTI claim is present
        if api_settings.JTI_CLAIM is not None:
            jti_claim = api_settings.JTI_CLAIM
            if jti_claim not in self.payload:
                raise TokenError(f"Token has no '{jti_claim}' claim")

    def verify_token_type(self):
        """
        Ensures that the token type claim is correct.
        """
        token_type = api_settings.TOKEN_TYPE_CLAIM
        try:
            token_type_value = self.payload[token_type]
        except KeyError:
            raise TokenError(f"Token has no '{token_type}' claim")

        if token_type_value != self.token_type:
            raise TokenError("Token has wrong type")

    def set_jti(self):
        """
        Populates the "jti" claim with a unique identifier.
        """
        if api_settings.JTI_CLAIM is not None:
            self.payload[api_settings.JTI_CLAIM] = uuid4().hex

    def set_exp(self, claim="exp", from_time=None, lifetime=None):
        """
        Updates the expiration time of the token.
        """
        if from_time is None:
            from_time = self.current_time

        if lifetime is None:
            lifetime = self.lifetime

        self.payload[claim] = datetime_to_epoch(from_time + lifetime)

    def set_iat(self, claim="iat", at_time=None):
        """
        Updates the issued at time of the token.
        """
        if at_time is None:
            at_time = self.current_time

        self.payload[claim] = datetime_to_epoch(at_time)

    def check_exp(self, claim="exp", current_time=None):
        """
        Checks whether the expiration time has passed.
        """
        if current_time is None:
            current_time = self.current_time

        try:
            claim_value = self.payload[claim]
        except KeyError:
            raise TokenError(f"Token has no '{claim}' claim")

        claim_time = datetime_from_epoch(claim_value)

        # Handle leeway
        leeway = self.token_backend.leeway
        if isinstance(leeway, timedelta):
            leeway_seconds = leeway.total_seconds()
        elif isinstance(leeway, (int, float)):
            leeway_seconds = leeway
        elif leeway is None:
            leeway_seconds = 0
        else:
            raise TokenBackendError("Leeway must be a timedelta, int, or float")

        if claim_time <= current_time - timedelta(seconds=leeway_seconds):
            raise TokenError(f"'{claim}' claim has expired")

    def get_token_backend(self):
        """
        Returns the token backend instance.
        """
        return token_backend

    @classmethod
    def for_user(cls, user):
        """
        Returns an authorization token for the given user.
        """
        user_id = getattr(user, api_settings.USER_ID_FIELD)

        # Always convert user_id to string
        user_id = str(user_id)

        token = cls()
        token[api_settings.USER_ID_CLAIM] = user_id

        # Check if revoke token claim should be included
        if api_settings.CHECK_REVOKE_TOKEN:
            token[api_settings.REVOKE_TOKEN_CLAIM] = get_md5_hash_password(user.password)

        return token


class BlacklistMixin:
    """
    Mixin that adds blacklist functionality to tokens.
    """

    def verify(self, *args, **kwargs):
        self.check_blacklist()
        super().verify(*args, **kwargs)

    def check_blacklist(self):
        """
        Checks if this token is blacklisted.
        """
        if not apps.is_installed("rest_framework_simplejwt.token_blacklist"):
            return

        jti = self.payload.get(api_settings.JTI_CLAIM)
        if jti is None:
            return

        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

        if BlacklistedToken.objects.filter(token__jti=jti).exists():
            raise TokenError("Token is blacklisted")

    def blacklist(self):
        """
        Blacklists the token.
        """
        if not apps.is_installed("rest_framework_simplejwt.token_blacklist"):
            return None, False

        from rest_framework_simplejwt.token_blacklist.models import (
            BlacklistedToken,
            OutstandingToken,
        )

        jti = self.payload.get(api_settings.JTI_CLAIM)
        exp = self.payload.get("exp")

        # Try to get or create outstanding token
        outstanding, created = OutstandingToken.objects.get_or_create(
            jti=jti,
            defaults={
                "token": str(self),
                "expires_at": datetime_from_epoch(exp),
                "created_at": self.current_time,
            },
        )

        # Try to get or create blacklisted token
        blacklisted_token, created = BlacklistedToken.objects.get_or_create(
            token=outstanding
        )

        return blacklisted_token, created

    @classmethod
    def for_user(cls, user):
        """
        Returns a token for the given user and adds it to the outstanding list.
        """
        token = super().for_user(user)

        if apps.is_installed("rest_framework_simplejwt.token_blacklist"):
            from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

            jti = token.payload.get(api_settings.JTI_CLAIM)
            exp = token.payload.get("exp")

            OutstandingToken.objects.create(
                user=user,
                jti=jti,
                token=str(token),
                expires_at=datetime_from_epoch(exp),
                created_at=token.current_time,
            )

        return token


class SlidingToken(BlacklistMixin, Token):
    """
    A sliding token that has a short-lived access portion and a longer-lived
    refresh portion.
    """

    token_type = "sliding"
    lifetime = api_settings.SLIDING_TOKEN_LIFETIME

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.token is None:
            # Set the refresh expiration claim
            self.set_exp(
                api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM,
                from_time=self.current_time,
                lifetime=api_settings.SLIDING_TOKEN_REFRESH_LIFETIME,
            )


class RefreshToken(BlacklistMixin, Token):
    """
    A refresh token that can be used to obtain new access tokens.
    """

    token_type = "refresh"
    lifetime = api_settings.REFRESH_TOKEN_LIFETIME
    no_copy_claims = (
        api_settings.TOKEN_TYPE_CLAIM,
        "exp",
        "iat",
        api_settings.JTI_CLAIM,
    )

    @property
    def access_token(self):
        """
        Returns an access token created from this refresh token.
        """
        access = AccessToken()

        # Copy claims from refresh token to access token
        for claim, value in self.payload.items():
            if claim not in self.no_copy_claims:
                access[claim] = value

        return access


class AccessToken(Token):
    """
    An access token used to authenticate requests.
    """

    token_type = "access"
    lifetime = api_settings.ACCESS_TOKEN_LIFETIME


class UntypedToken(Token):
    """
    A token that does not check or set the token type claim. Useful for
    token verification endpoints.
    """

    token_type = "untyped"
    lifetime = timedelta(seconds=0)

    def verify_token_type(self):
        """
        Don't verify token type for untyped tokens.
        """
        pass
