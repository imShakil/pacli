from importlib.metadata import (
    version as importlib_version,
    PackageNotFoundError as ImportlibPackageNotFoundError,
)

try:
    __version__ = importlib_version("pacli-tool")
except ImportlibPackageNotFoundError:
    __version__ = "unknown"
