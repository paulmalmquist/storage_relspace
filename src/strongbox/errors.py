"""Domain errors. Each maps to one HTTP status and one stable machine-readable code."""

from __future__ import annotations


class StrongboxError(Exception):
    status: int = 500
    code: str = "internal_error"

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or self.code)
        self.detail = detail or self.code


class ConfigurationError(StrongboxError):
    code = "configuration_error"


class Unauthenticated(StrongboxError):
    status = 401
    code = "unauthenticated"


class AccessDenied(StrongboxError):
    status = 403
    code = "forbidden"


class ContentWithheld(StrongboxError):
    """The caller may see that an object exists and its metadata, but not its CUI content."""

    status = 403
    code = "content_withheld"


class NotFound(StrongboxError):
    status = 404
    code = "not_found"


class Conflict(StrongboxError):
    status = 409
    code = "conflict"


class PreconditionFailed(StrongboxError):
    status = 412
    code = "precondition_failed"


class PreconditionRequired(StrongboxError):
    status = 428
    code = "precondition_required"


class PayloadTooLarge(StrongboxError):
    status = 413
    code = "payload_too_large"


class ValidationFailed(StrongboxError):
    status = 422
    code = "validation_failed"


class IntegrityViolation(StrongboxError):
    """Ciphertext, wrapped key, or audit chain failed authentication. Treat as a security event."""

    status = 500
    code = "integrity_violation"
