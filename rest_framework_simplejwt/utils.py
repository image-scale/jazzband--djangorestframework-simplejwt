import hashlib
from calendar import timegm
from datetime import datetime, timezone

from django.conf import settings
from django.utils.functional import lazy


def make_utc(dt):
    """
    Make a naive datetime into an aware UTC datetime if Django is configured
    to use timezones.
    """
    if settings.USE_TZ and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def aware_utcnow():
    """
    Return the current UTC time as an aware datetime if USE_TZ is True,
    otherwise return a naive datetime.
    """
    dt = datetime.now(tz=timezone.utc)
    if not settings.USE_TZ:
        return dt.replace(tzinfo=None)
    return dt


def datetime_to_epoch(dt):
    """
    Convert a datetime object to Unix timestamp (seconds since epoch).
    """
    return timegm(dt.utctimetuple())


def datetime_from_epoch(ts):
    """
    Convert a Unix timestamp (seconds since epoch) to a datetime object.
    """
    dt = datetime.utcfromtimestamp(ts)
    if settings.USE_TZ:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def format_lazy(s, *args, **kwargs):
    """
    Lazily format a string with the given arguments.
    """
    return lazy(lambda: s.format(*args, **kwargs), str)()


def get_md5_hash_password(password):
    """
    Get MD5 hash of password for token revocation check.
    """
    return hashlib.md5(password.encode()).hexdigest()
