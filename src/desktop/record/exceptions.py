"""Custom exception types for the record module."""


class RecordError(Exception):
    """Base exception for all record operations."""


class RecordValidationError(RecordError):
    """Raised when a record fails schema validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Record validation failed: {'; '.join(errors)}")


class RenderingError(RecordError):
    """Raised when PDF rendering fails."""


class HistoryError(RecordError):
    """Raised when history manipulation fails."""


class UnknownClassificationError(RecordError):
    """Raised when unknown file classification fails."""
