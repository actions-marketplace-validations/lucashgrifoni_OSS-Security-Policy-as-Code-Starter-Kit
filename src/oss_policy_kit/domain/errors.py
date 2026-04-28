"""User-facing errors without leaking stack traces by default."""


class OssPolicyKitError(Exception):
    """Base error for CLI messaging."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class InvalidInputError(OssPolicyKitError):
    """Invalid CLI arguments or paths."""


class LoadError(OssPolicyKitError):
    """Profile, catalog, or waiver load failure."""


class ProfileLoadError(LoadError):
    """External profile file failed structural or schema validation."""


class CollectionPermissionError(OssPolicyKitError):
    """Platform API denied access (missing scopes or repository visibility)."""


class RateLimitError(OssPolicyKitError):
    """Platform API rate limit exceeded."""


class CollectionNetworkError(OssPolicyKitError):
    """Evidence collection failed due to a network or transport error."""
