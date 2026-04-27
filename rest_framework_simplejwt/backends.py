from datetime import timedelta

import jwt
from jwt import algorithms

from .exceptions import TokenBackendError, TokenBackendExpiredToken

try:
    from jwt import PyJWKClient, PyJWKClientError
    JWK_CLIENT_AVAILABLE = True
except ImportError:
    JWK_CLIENT_AVAILABLE = False
    PyJWKClient = None
    PyJWKClientError = None


ALLOWED_ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
}


class TokenBackend:
    """
    A class that provides encoding and decoding of JWTs.
    """

    def __init__(
        self,
        algorithm,
        signing_key=None,
        verifying_key="",
        audience=None,
        issuer=None,
        jwk_url=None,
        leeway=0,
        json_encoder=None,
    ):
        self._validate_algorithm(algorithm)

        self.algorithm = algorithm
        self.signing_key = signing_key
        self.verifying_key = verifying_key
        self.audience = audience
        self.issuer = issuer
        self.jwk_url = jwk_url
        self.leeway = leeway
        self.json_encoder = json_encoder

        if self.jwk_url and JWK_CLIENT_AVAILABLE:
            self.jwks_client = PyJWKClient(self.jwk_url)
        else:
            self.jwks_client = None

    def _validate_algorithm(self, algorithm):
        """
        Ensure the algorithm is valid and, for asymmetric algorithms,
        that cryptography is installed.
        """
        if algorithm not in ALLOWED_ALGORITHMS:
            raise TokenBackendError(f"Unrecognized algorithm type '{algorithm}'")

        if algorithm.startswith(("RS", "ES")):
            if not algorithms.has_crypto:
                raise TokenBackendError(
                    f"You must have cryptography installed to use {algorithm}."
                )

    def _get_verifying_key(self, token):
        """
        Get the verifying key, possibly from JWK endpoint.
        """
        if self.jwks_client:
            try:
                signing_key = self.jwks_client.get_signing_key_from_jwt(token)
                return signing_key.key
            except PyJWKClientError:
                raise TokenBackendError("Token is invalid")

        if self.algorithm.startswith("HS"):
            return self.signing_key

        return self.verifying_key

    def encode(self, payload):
        """
        Returns an encoded token for the given payload.
        """
        jwt_payload = payload.copy()

        # Add audience and issuer if configured
        if self.audience is not None:
            jwt_payload["aud"] = self.audience
        if self.issuer is not None:
            jwt_payload["iss"] = self.issuer

        token = jwt.encode(
            jwt_payload,
            self.signing_key,
            algorithm=self.algorithm,
            json_encoder=self.json_encoder,
        )

        # Handle both old PyJWT (returns bytes) and new PyJWT (returns str)
        if isinstance(token, bytes):
            return token.decode("utf-8")
        return token

    def decode(self, token, verify=True):
        """
        Returns the decoded payload from the given token.
        """
        try:
            return jwt.decode(
                token,
                self._get_verifying_key(token),
                algorithms=[self.algorithm],
                options={
                    "verify_signature": verify,
                    "verify_exp": verify,
                    "verify_aud": verify and self.audience is not None,
                    "verify_iss": verify and self.issuer is not None,
                },
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
            )
        except jwt.ExpiredSignatureError:
            raise TokenBackendExpiredToken("Token has expired")
        except jwt.InvalidAlgorithmError:
            raise TokenBackendError("Invalid algorithm specified")
        except jwt.InvalidTokenError:
            raise TokenBackendError("Token is invalid")
