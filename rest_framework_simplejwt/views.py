from django.utils.module_loading import import_string
from rest_framework import generics, status
from rest_framework.response import Response

from .exceptions import InvalidToken, TokenError
from .serializers import (
    TokenBlacklistSerializer,
    TokenObtainPairSerializer,
    TokenObtainSlidingSerializer,
    TokenRefreshSerializer,
    TokenRefreshSlidingSerializer,
    TokenVerifySerializer,
)


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None
    _serializer_class = ""

    www_authenticate_realm = "api"

    def get_serializer_class(self):
        """
        Returns the class to use for the serializer.
        """
        if self.serializer_class is not None:
            return self.serializer_class

        try:
            return import_string(self._serializer_class)
        except ImportError:
            msg = f"Could not import serializer '{self._serializer_class}'"
            raise ImportError(msg)

    def get_authenticate_header(self, request):
        return f'Bearer realm="{self.www_authenticate_realm}"'

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TokenObtainPairView(TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenObtainPairSerializer"


token_obtain_pair = TokenObtainPairView.as_view()


class TokenRefreshView(TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenRefreshSerializer"


token_refresh = TokenRefreshView.as_view()


class TokenObtainSlidingView(TokenViewBase):
    """
    Takes a set of user credentials and returns a sliding JSON web token to
    prove the authentication of those credentials.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer"


token_obtain_sliding = TokenObtainSlidingView.as_view()


class TokenRefreshSlidingView(TokenViewBase):
    """
    Takes a sliding JSON web token and returns a new, refreshed version if the
    token's refresh period has not expired.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer"


token_refresh_sliding = TokenRefreshSlidingView.as_view()


class TokenVerifyView(TokenViewBase):
    """
    Takes a token and indicates if it is valid. This view provides no
    information about a token's fitness for a particular use.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenVerifySerializer"


token_verify = TokenVerifyView.as_view()


class TokenBlacklistView(TokenViewBase):
    """
    Takes a refresh type JSON web token and blacklists it.
    """

    _serializer_class = "rest_framework_simplejwt.serializers.TokenBlacklistSerializer"


token_blacklist = TokenBlacklistView.as_view()
