from .backends import TokenBackend
from .settings import api_settings


def get_default_token_backend():
    """
    Create and return a TokenBackend using the default settings.
    """
    return TokenBackend(
        algorithm=api_settings.ALGORITHM,
        signing_key=api_settings.SIGNING_KEY,
        verifying_key=api_settings.VERIFYING_KEY,
        audience=api_settings.AUDIENCE,
        issuer=api_settings.ISSUER,
        jwk_url=api_settings.JWK_URL,
        leeway=api_settings.LEEWAY,
        json_encoder=api_settings.JSON_ENCODER,
    )


# Default token backend instance
token_backend = get_default_token_backend()
