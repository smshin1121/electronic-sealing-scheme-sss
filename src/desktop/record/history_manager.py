"""History accumulation manager for seal/unseal/reseal events.

All functions follow the immutability rule: they accept dicts and
return *new* dicts without modifying the originals.
"""

from __future__ import annotations

import copy
import re

from .exceptions import HistoryError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEAL_TYPE_ABBR: dict[str, str] = {
    "Sealing": "S",
    "Unsealing": "U",
    "Resealing": "R",
}
_VALID_SEAL_TYPES = frozenset(_SEAL_TYPE_ABBR.keys())
_SUMMARY_PATTERN = re.compile(r"^S(\d+)U(\d+)R(\d+)$")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_initial_history(event: dict) -> dict:
    """Create a new history object with the first sealing event.

    The event must have ``seal_type == "Sealing"``.

    Args:
        event: A dict with keys ``seal_type``, ``start_time``,
            ``end_time``, and ``investigator``.

    Returns:
        A new history dict with ``summary`` and ``events`` list.

    Raises:
        HistoryError: If the event is not a Sealing event or is missing
            required fields.
    """
    _validate_event_fields(event)

    if event.get("seal_type") != "Sealing":
        raise HistoryError(
            f"Initial history event must be Sealing, "
            f"got '{event.get('seal_type')}'"
        )

    first_event = _build_event(event, event_id=1)

    history: dict = {
        "summary": "S1U0R0",
        "events": [first_event],
    }
    return history


def append_event(history: dict, event: dict) -> dict:
    """Append a new event to an existing history (immutable).

    Previous events are deep-copied and never modified.  The new event
    receives an auto-incremented ``id`` based on the current array length.

    Args:
        history: Existing history dict with ``summary`` and ``events``.
        event: A dict with keys ``seal_type``, ``start_time``,
            ``end_time``, and ``investigator``.

    Returns:
        A new history dict with the event appended and summary updated.

    Raises:
        HistoryError: If the event is invalid or the history structure
            is malformed.
    """
    _validate_event_fields(event)
    _validate_history_structure(history)

    prev_events = copy.deepcopy(history["events"])
    new_id = len(prev_events) + 1
    new_event = _build_event(event, event_id=new_id)

    new_events = [*prev_events, new_event]
    new_history: dict = {
        "summary": _compute_summary(new_events),
        "events": new_events,
    }
    return new_history


def update_summary(history: dict) -> dict:
    """Recompute the summary string from the events array (immutable).

    Useful when the summary may be stale or needs recalculation.

    Args:
        history: Existing history dict.

    Returns:
        A new history dict with the recalculated summary.
    """
    _validate_history_structure(history)

    events = copy.deepcopy(history["events"])
    new_history: dict = {
        "summary": _compute_summary(events),
        "events": events,
    }
    return new_history


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_event(event: dict, event_id: int) -> dict:
    """Build a normalized event dict with the given id."""
    return {
        "id": event_id,
        "seal_type": event["seal_type"],
        "start_time": event["start_time"],
        "end_time": event["end_time"],
        "investigator": event["investigator"],
    }


def _compute_summary(events: list[dict]) -> str:
    """Compute the S{n}U{m}R{k} summary from an events list."""
    counts: dict[str, int] = {"S": 0, "U": 0, "R": 0}

    for ev in events:
        seal_type = ev.get("seal_type", "")
        abbr = _SEAL_TYPE_ABBR.get(seal_type)
        if abbr is None:
            raise HistoryError(
                f"Unknown seal_type '{seal_type}' in event id={ev.get('id')}"
            )
        counts[abbr] += 1

    return f"S{counts['S']}U{counts['U']}R{counts['R']}"


def _validate_event_fields(event: dict) -> None:
    """Raise HistoryError if required event fields are missing."""
    required = ("seal_type", "start_time", "end_time", "investigator")
    missing = [f for f in required if not event.get(f)]
    if missing:
        raise HistoryError(f"Event missing required fields: {missing}")

    seal_type = event.get("seal_type", "")
    if seal_type not in _VALID_SEAL_TYPES:
        raise HistoryError(
            f"Invalid seal_type '{seal_type}'. "
            f"Must be one of {sorted(_VALID_SEAL_TYPES)}"
        )


def _validate_history_structure(history: dict) -> None:
    """Raise HistoryError if history dict is malformed."""
    if not isinstance(history, dict):
        raise HistoryError("History must be a dict")
    if "events" not in history:
        raise HistoryError("History missing 'events' key")
    if not isinstance(history["events"], list):
        raise HistoryError("History 'events' must be a list")
    if "summary" not in history:
        raise HistoryError("History missing 'summary' key")
