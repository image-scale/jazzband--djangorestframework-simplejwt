from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("djangorestframework_simplejwt")
except PackageNotFoundError:
    __version__ = None
