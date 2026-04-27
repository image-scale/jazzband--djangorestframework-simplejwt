from django.core.management.base import BaseCommand
from django.utils import timezone

from rest_framework_simplejwt.token_blacklist.models import OutstandingToken


class Command(BaseCommand):
    help = "Flushes any expired tokens from the outstanding token list"

    def handle(self, *args, **kwargs):
        OutstandingToken.objects.filter(expires_at__lte=timezone.now()).delete()
