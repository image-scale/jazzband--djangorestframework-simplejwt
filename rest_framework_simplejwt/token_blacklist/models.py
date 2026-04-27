from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class OutstandingToken(models.Model):
    """
    A model to track outstanding tokens that have been issued.
    """

    id = models.BigAutoField(primary_key=True, serialize=False)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    jti = models.CharField(unique=True, max_length=255)
    token = models.TextField()

    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ("user",)
        abstract = False

    def __str__(self):
        return f"Token for {self.user} ({self.jti})"


class BlacklistedToken(models.Model):
    """
    A model to track blacklisted tokens.
    """

    id = models.BigAutoField(primary_key=True, serialize=False)

    token = models.OneToOneField(
        OutstandingToken,
        on_delete=models.CASCADE,
    )

    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = False

    def __str__(self):
        return f"Blacklisted token for {self.token.user}"
