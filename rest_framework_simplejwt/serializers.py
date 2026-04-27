from django.apps import apps
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers

from .exceptions import TokenError
from .settings import api_settings
from .tokens import RefreshToken, SlidingToken, UntypedToken
from .utils import datetime_from_epoch, get_md5_hash_password


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("style", {})
        kwargs["style"]["input_type"] = "password"
        kwargs["write_only"] = True
        super().__init__(*args, **kwargs)


class TokenObtainSerializer(serializers.Serializer):
    username_field = get_user_model().USERNAME_FIELD
    token_class = None

    default_error_messages = {
        "no_active_account": _("No active account found with the given credentials")
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields["password"] = PasswordField()

    def validate(self, attrs):
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            "password": attrs["password"],
        }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if self.user is None or (
            api_settings.CHECK_USER_IS_ACTIVE and not self.user.is_active
        ):
            # Call ON_LOGIN_FAILED hook if set
            on_login_failed = api_settings.ON_LOGIN_FAILED
            if on_login_failed is not None:
                # Mask the password with 20 asterisks and exclude request
                masked_credentials = {
                    self.username_field: attrs[self.username_field],
                    "password": "*" * 20,
                }
                on_login_failed(masked_credentials, self.context.get("request"))

            raise exceptions.AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )

        return {}

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)


class TokenObtainPairSerializer(TokenObtainSerializer):
    token_class = RefreshToken

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TokenObtainSlidingSerializer(TokenObtainSerializer):
    token_class = SlidingToken

    def validate(self, attrs):
        data = super().validate(attrs)

        token = self.get_token(self.user)

        data["token"] = str(token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)

    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs["refresh"])

        # Check user still exists and is active
        user_id = refresh.payload.get(api_settings.USER_ID_CLAIM)
        if user_id is not None:
            try:
                User = get_user_model()
                user = User.objects.get(**{api_settings.USER_ID_FIELD: user_id})
                if not user.is_active:
                    raise exceptions.AuthenticationFailed(
                        _("No active account found with the given credentials"),
                        "no_active_account",
                    )

                # Check revoke token claim if enabled
                if api_settings.CHECK_REVOKE_TOKEN:
                    revoke_claim = refresh.payload.get(api_settings.REVOKE_TOKEN_CLAIM)
                    current_hash = get_md5_hash_password(user.password)
                    if revoke_claim != current_hash:
                        # Blacklist the token if enabled
                        if api_settings.BLACKLIST_AFTER_ROTATION:
                            refresh.blacklist()
                        raise exceptions.AuthenticationFailed(
                            _("The user's password has been changed."),
                            "password_changed",
                        )
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    _("No active account found with the given credentials"),
                    "no_active_account",
                )

        data = {"access": str(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, this will fail silently
                    pass

            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()

            # Create an OutstandingToken for the new refresh token
            if api_settings.BLACKLIST_AFTER_ROTATION:
                if apps.is_installed("rest_framework_simplejwt.token_blacklist"):
                    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

                    jti = refresh.payload.get(api_settings.JTI_CLAIM)
                    exp = refresh.payload.get("exp")

                    OutstandingToken.objects.create(
                        user=None,  # User may not be known from token alone
                        jti=jti,
                        token=str(refresh),
                        expires_at=datetime_from_epoch(exp),
                        created_at=refresh.current_time,
                    )

            data["refresh"] = str(refresh)

        return data


class TokenRefreshSlidingSerializer(serializers.Serializer):
    token = serializers.CharField()

    token_class = SlidingToken

    def validate(self, attrs):
        token = self.token_class(attrs["token"])

        # Check user still exists and is active
        user_id = token.payload.get(api_settings.USER_ID_CLAIM)
        if user_id is not None:
            try:
                User = get_user_model()
                user = User.objects.get(**{api_settings.USER_ID_FIELD: user_id})
                if not user.is_active:
                    raise exceptions.AuthenticationFailed(
                        _("No active account found with the given credentials"),
                        "no_active_account",
                    )

                # Check revoke token claim if enabled
                if api_settings.CHECK_REVOKE_TOKEN:
                    revoke_claim = token.payload.get(api_settings.REVOKE_TOKEN_CLAIM)
                    current_hash = get_md5_hash_password(user.password)
                    if revoke_claim != current_hash:
                        # Blacklist the token if enabled
                        if api_settings.BLACKLIST_AFTER_ROTATION:
                            token.blacklist()
                        raise exceptions.AuthenticationFailed(
                            _("The user's password has been changed."),
                            "password_changed",
                        )
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    _("No active account found with the given credentials"),
                    "no_active_account",
                )

        # Check that the refresh exp claim hasn't expired
        token.check_exp(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM)

        # Update the access token expiration
        token.set_exp()
        token.set_iat()

        return {"token": str(token)}


class TokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = UntypedToken(attrs["token"])

        # Check if blacklist is enabled and token is blacklisted
        if api_settings.BLACKLIST_AFTER_ROTATION:
            if apps.is_installed("rest_framework_simplejwt.token_blacklist"):
                jti = token.payload.get(api_settings.JTI_CLAIM)
                if jti:
                    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
                    if BlacklistedToken.objects.filter(token__jti=jti).exists():
                        raise serializers.ValidationError("Token is blacklisted")

        return {}


class TokenBlacklistSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs["refresh"])

        try:
            refresh.blacklist()
        except AttributeError:
            # If blacklist app not installed, this will fail silently
            pass

        return {}
