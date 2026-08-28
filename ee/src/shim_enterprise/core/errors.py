"""Cross-domain failure categories that do not encode protocol responses."""


class ShimError(Exception):
    """Base class for intentional product failures."""


class ConfigurationError(ShimError):
    """Required runtime configuration is absent or invalid."""


class PersistenceError(ShimError):
    """Authoritative durable state could not be read or committed."""


class IdentityConflictError(PersistenceError):
    """An idempotent identity conflicts with existing durable state."""
