from django.contrib import admin

from .models import BlacklistedToken, OutstandingToken


@admin.register(OutstandingToken)
class OutstandingTokenAdmin(admin.ModelAdmin):
    list_display = ("jti", "user", "created_at", "expires_at")
    search_fields = ("jti", "user__username")
    ordering = ("user",)


@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "blacklisted_at")
    search_fields = ("token__jti",)
