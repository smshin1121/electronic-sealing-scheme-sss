"""Pure helpers for rendering record previews in the wizards.

The canonical record schema stores history as a dict::

    {"summary": "S1U1R0", "events": [{"seal_type": ..., "start_time":
    ..., "end_time": ..., "investigator": ...}, ...]}

Legacy (fallback-built) records store history as a flat list of
``{"event": ..., "timestamp": ..., "actor": ...}`` dicts with the
summary at the record top level. These helpers normalize both shapes
so the U6/R6 preview never iterates a dict's string keys.

No tkinter imports — keep this module unit-testable headlessly.
"""

from __future__ import annotations

from typing import Any


def extract_history_view(record: dict[str, Any]) -> tuple[list[dict[str, str]], str]:
    """Return normalized ``(events, summary)`` from a record's history.

    Each returned event dict has the keys ``type``, ``time`` and
    ``actor`` regardless of whether the source event used the canonical
    (seal_type/start_time/investigator) or legacy
    (event/timestamp/actor) field names.

    Args:
        record: A seal/unseal/reseal record dict (may be empty).

    Returns:
        A tuple of (normalized event list, summary string). Missing
        data yields an empty list and ``"N/A"``.
    """
    history = record.get("history", {})

    if isinstance(history, dict):
        raw_events = history.get("events", [])
        summary = history.get("summary") or record.get("summary") or "N/A"
    elif isinstance(history, list):
        raw_events = history
        summary = record.get("summary") or "N/A"
    else:
        raw_events = []
        summary = record.get("summary") or "N/A"

    events: list[dict[str, str]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            continue
        events.append({
            "type": str(event.get("seal_type") or event.get("event") or ""),
            "time": str(
                event.get("start_time") or event.get("timestamp") or ""
            ),
            "actor": str(
                event.get("investigator") or event.get("actor") or ""
            ),
        })
    return events, str(summary)


def extract_case_number(record: dict[str, Any]) -> str:
    """Return the case number from canonical or legacy record layout."""
    case_info = record.get("case_info")
    if isinstance(case_info, dict) and case_info.get("case_number"):
        return str(case_info["case_number"])
    return str(record.get("case_number", ""))
