"""Unit tests for history accumulation manager.

Validates:
  - create_initial_history() produces summary "S1U0R0" and 1 event
  - append_event() preserves previous events (deep copy / immutability)
  - update_summary() computes correct format (S1U2R1 etc.)
  - Full seal -> unseal -> reseal scenario
"""

from __future__ import annotations

import copy

import pytest

from desktop.record.exceptions import HistoryError
from desktop.record.history_manager import (
    append_event,
    create_initial_history,
    update_summary,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seal_event(investigator: str = "Kim") -> dict:
    return {
        "seal_type": "Sealing",
        "start_time": "2026-04-01T10:00:00Z",
        "end_time": "2026-04-01T11:00:00Z",
        "investigator": investigator,
    }


def _unseal_event(investigator: str = "Park") -> dict:
    return {
        "seal_type": "Unsealing",
        "start_time": "2026-04-02T10:00:00Z",
        "end_time": "2026-04-02T11:00:00Z",
        "investigator": investigator,
    }


def _reseal_event(investigator: str = "Choi") -> dict:
    return {
        "seal_type": "Resealing",
        "start_time": "2026-04-03T10:00:00Z",
        "end_time": "2026-04-03T11:00:00Z",
        "investigator": investigator,
    }


# ---------------------------------------------------------------------------
# Tests: create_initial_history
# ---------------------------------------------------------------------------


class TestCreateInitialHistory:
    """create_initial_history produces summary S1U0R0, 1 event."""

    def test_summary_format(self) -> None:
        history = create_initial_history(_seal_event())
        assert history["summary"] == "S1U0R0"

    def test_events_length(self) -> None:
        history = create_initial_history(_seal_event())
        assert len(history["events"]) == 1

    def test_event_id_is_one(self) -> None:
        history = create_initial_history(_seal_event())
        assert history["events"][0]["id"] == 1

    def test_event_seal_type(self) -> None:
        history = create_initial_history(_seal_event())
        assert history["events"][0]["seal_type"] == "Sealing"

    def test_non_sealing_event_raises(self) -> None:
        with pytest.raises(HistoryError, match="Sealing"):
            create_initial_history(_unseal_event())

    def test_missing_fields_raises(self) -> None:
        with pytest.raises(HistoryError):
            create_initial_history({"seal_type": "Sealing"})


# ---------------------------------------------------------------------------
# Tests: append_event immutability (deep copy)
# ---------------------------------------------------------------------------


class TestAppendEventImmutability:
    """append_event() must not mutate the original history."""

    def test_original_history_unchanged(self) -> None:
        original = create_initial_history(_seal_event())
        original_snapshot = copy.deepcopy(original)

        _ = append_event(original, _unseal_event())

        assert original == original_snapshot, (
            "Original history was mutated by append_event()"
        )

    def test_original_events_not_shared(self) -> None:
        """New history events list must be a different object."""
        original = create_initial_history(_seal_event())
        new_history = append_event(original, _unseal_event())

        assert original["events"] is not new_history["events"]

    def test_deep_copy_of_events(self) -> None:
        """Modifying new history events must not affect original."""
        original = create_initial_history(_seal_event())
        new_history = append_event(original, _unseal_event())

        new_history["events"][0]["investigator"] = "MUTATED"
        assert original["events"][0]["investigator"] != "MUTATED"

    def test_append_increments_event_count(self) -> None:
        h = create_initial_history(_seal_event())
        h2 = append_event(h, _unseal_event())
        assert len(h2["events"]) == 2
        assert len(h["events"]) == 1  # original unchanged

    def test_event_id_auto_increments(self) -> None:
        h = create_initial_history(_seal_event())
        h2 = append_event(h, _unseal_event())
        assert h2["events"][1]["id"] == 2


# ---------------------------------------------------------------------------
# Tests: update_summary format
# ---------------------------------------------------------------------------


class TestUpdateSummary:
    """update_summary() must produce correct S{n}U{m}R{k} format."""

    def test_s1_summary(self) -> None:
        h = create_initial_history(_seal_event())
        updated = update_summary(h)
        assert updated["summary"] == "S1U0R0"

    def test_s1u1_summary(self) -> None:
        h = create_initial_history(_seal_event())
        h = append_event(h, _unseal_event())
        updated = update_summary(h)
        assert updated["summary"] == "S1U1R0"

    def test_s1u2r1_summary(self) -> None:
        h = create_initial_history(_seal_event())
        h = append_event(h, _unseal_event())
        h = append_event(h, _unseal_event())
        h = append_event(h, _reseal_event())
        updated = update_summary(h)
        assert updated["summary"] == "S1U2R1"

    def test_update_summary_is_immutable(self) -> None:
        h = create_initial_history(_seal_event())
        h_snapshot = copy.deepcopy(h)
        _ = update_summary(h)
        assert h == h_snapshot


# ---------------------------------------------------------------------------
# Tests: full seal -> unseal -> reseal scenario
# ---------------------------------------------------------------------------


class TestSealUnsealResealScenario:
    """End-to-end history accumulation through multiple procedures."""

    def test_full_cycle(self) -> None:
        # Seal
        h = create_initial_history(_seal_event())
        assert h["summary"] == "S1U0R0"
        assert len(h["events"]) == 1

        # Unseal
        h = append_event(h, _unseal_event())
        assert h["summary"] == "S1U1R0"
        assert len(h["events"]) == 2

        # Reseal
        h = append_event(h, _reseal_event())
        assert h["summary"] == "S1U1R1"
        assert len(h["events"]) == 3

        # Verify event IDs are sequential
        for idx, ev in enumerate(h["events"], start=1):
            assert ev["id"] == idx

    def test_multiple_unseal_reseal_cycles(self) -> None:
        h = create_initial_history(_seal_event())

        # 2 unseal-reseal cycles
        for _ in range(2):
            h = append_event(h, _unseal_event())
            h = append_event(h, _reseal_event())

        assert h["summary"] == "S1U2R2"
        assert len(h["events"]) == 5

    def test_invalid_event_type_raises(self) -> None:
        h = create_initial_history(_seal_event())
        with pytest.raises(HistoryError):
            append_event(h, {
                "seal_type": "InvalidType",
                "start_time": "2026-04-01T10:00:00Z",
                "end_time": "2026-04-01T11:00:00Z",
                "investigator": "Kim",
            })
