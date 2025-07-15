from importlib.metadata import version, PackageNotFoundError, metadata

try:
    __version__ = version("pacli-tool")
    __metadata__ = metadata("pacli-tool")
except PackageNotFoundError:
    __version__ = "Unknown"
