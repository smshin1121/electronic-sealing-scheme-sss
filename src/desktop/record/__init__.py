"""Record module for the digital evidence electronic sealing system.

Re-exports the primary public API for record construction, history
management, PDF rendering, and unknown file classification.
"""

from .exceptions import (
    HistoryError,
    RecordError,
    RecordValidationError,
    RenderingError,
    UnknownClassificationError,
)
from .history_manager import (
    append_event,
    create_initial_history,
    update_summary,
)
from .pdf_renderer import render_record_pdf
from .record_builder import (
    build_reseal_record,
    build_seal_record,
    build_unseal_record,
    create_seal_id,
    validate_record,
)
from .unknown_classifier import identify_unknown_files

__all__ = [
    # Record building
    "create_seal_id",
    "build_seal_record",
    "build_unseal_record",
    "build_reseal_record",
    "validate_record",
    # History management
    "create_initial_history",
    "append_event",
    "update_summary",
    # PDF rendering
    "render_record_pdf",
    # Unknown file classification
    "identify_unknown_files",
    # Exceptions
    "RecordError",
    "RecordValidationError",
    "RenderingError",
    "HistoryError",
    "UnknownClassificationError",
]
