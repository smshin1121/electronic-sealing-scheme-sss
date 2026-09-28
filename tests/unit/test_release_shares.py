"""Which stored shares a release tries, and in which order (stage F, F1).

Unit tests of :mod:`web.release_shares`: candidates of the deciding
generation G first, then the other generations, highest first, the lower
slot first within one; a stored value is a candidate only when it carries
its slot's index prefix; the admin pairs are every usable s4 with every
usable share of another slot; the first attempt whose recombination
matches the commitment wins; the audit notes name the generations.
"""

from __future__ import annotations

import pytest

from web.models.share_models import StoredShare
from web.release_shares import (
    MIN_TRIED_NOTE_BUDGET,
    admin_attempts,
    admin_pairs,
    admin_pool,
    admin_shares,
    admin_slots,
    as_stored_shares,
    by_preference,
    filled_slots,
    first_match,
    generation_0_admin_shares,
    generation_note,
    owner_attempts,
    owner_shares,
    released_note,
    slot_share,
    tried_note,
)


def _share(index: int, generation: int, data: str | None = None) -> StoredShare:
    value = data if data is not None else f"{index}-{generation:02x}" + "ab" * 31
    return StoredShare(index, generation, value)


class TestPreference:
    def test_generation_g_first_then_the_others_highest_first(self) -> None:
        rows = [_share(1, 0), _share(1, 3), _share(1, 2), _share(1, 5)]

        assert [r.generation for r in by_preference(rows, 2)] == [2, 5, 3, 0]

    def test_without_generation_g_the_highest_comes_first(self) -> None:
        rows = [_share(1, 1), _share(1, 4), _share(1, 0)]

        assert [r.generation for r in by_preference(rows, 9)] == [4, 1, 0]

    def test_the_lower_slot_comes_first_within_a_generation(self) -> None:
        rows = [_share(2, 1), _share(1, 2), _share(1, 1), _share(2, 2)]

        assert [(r.index, r.generation) for r in by_preference(rows, 1)] == [
            (1, 1), (2, 1), (1, 2), (2, 2)]


class TestOwnerShares:
    def test_no_stored_owner_share(self) -> None:
        assert owner_shares([]) == ((), "owner_share_missing")
        assert owner_shares([_share(1, 0, "")]) == ((), "owner_share_missing")
        assert owner_shares([_share(2, 1)]) == ((), "owner_share_missing")

    def test_only_malformed_owner_shares(self) -> None:
        rows = [_share(1, 0, "2-" + "ab" * 32), _share(1, 1, "ab" * 32)]

        assert owner_shares(rows) == ((), "owner_share_malformed")

    def test_malformed_rows_are_never_candidates(self) -> None:
        good = _share(1, 2)
        rows = [_share(1, 0, "4-" + "ab" * 32), good]

        assert owner_shares(rows) == ((good,), "")


class TestAdminPool:
    @pytest.mark.parametrize("rows, problem", [
        ([_share(1, 1)], "admin_share_missing"),
        ([_share(1, 1), _share(4, 1, "1-" + "ab" * 32)], "admin_share_malformed"),
        ([_share(4, 1)], "other_share_missing"),
        ([_share(4, 1), _share(2, 1, "1-" + "ab" * 32)], "other_share_malformed"),
    ])
    def test_the_v1_1_reasons_are_kept(self, rows, problem: str) -> None:
        assert admin_pool(rows) == (None, problem)

    def test_every_usable_s4_pairs_with_every_usable_other_share(self) -> None:
        rows = [_share(4, 1), _share(4, 2), _share(1, 1), _share(2, 1),
                _share(1, 2), _share(2, 0, "4-" + "ab" * 32)]
        pool, problem = admin_pool(rows)

        pairs = admin_pairs(pool, 2)

        assert problem == ""
        assert [(o.index, o.generation, a.generation) for o, a in pairs] == [
            (1, 2, 2), (1, 1, 2), (2, 1, 2),
            (1, 2, 1), (1, 1, 1), (2, 1, 1)]


class TestSmallHelpers:
    def test_generation_notes(self) -> None:
        assert generation_note((_share(1, 2),)) == "share 1 of generation 2"
        assert generation_note((_share(1, 1), _share(4, 2))) == (
            "share 1 of generation 1, share 4 of generation 2")
        assert generation_note(()) == ""

    def test_tried_notes(self) -> None:
        owner = owner_attempts([_share(1, 0), _share(1, 2)], 2, "2-ab")
        pairs = admin_attempts([(_share(2, 1), _share(4, 2))])

        assert tried_note(owner) == (
            "tried: share 1 of generation 2 | share 1 of generation 0")
        assert tried_note(pairs) == (
            "tried: share 2 of generation 1 + share 4 of generation 2")
        assert tried_note([((), ["2-ab", "3-cd"])]) == ""
        assert tried_note([]) == ""

    def test_a_long_tried_note_is_bounded(self) -> None:
        # Codex stage F review, R1-1: twenty stored owner shares must not push
        # the TSA rule out of the 500-character audit detail.
        owner = owner_attempts(
            [StoredShare(1, generation, f"1-{generation:02x}") for generation in range(1, 21)],
            21, "2-ab")

        note = tried_note(owner)

        assert len(note) <= 200
        assert note.startswith("tried: share 1 of generation 20 | share 1 of generation 19")
        assert note.endswith("more)")
        kept = note.count("share 1 of generation")
        assert note.endswith(f"| ... ({20 - kept} more)")
        # Round 2, N1: at the smallest budget one owner entry still fits; an
        # administrator pair does not, and then the count does.
        assert tried_note(owner, budget=MIN_TRIED_NOTE_BUDGET) == (
            "tried: share 1 of generation 20 | ... (19 more)")
        pairs = [((StoredShare(2, g, f"2-{g:02x}"), StoredShare(4, g, f"4-{g:02x}")),
                  [f"2-{g:02x}", f"4-{g:02x}"]) for g in range(20, 0, -1)]
        count = tried_note(pairs, budget=MIN_TRIED_NOTE_BUDGET)
        assert count == "tried: 20 stored share combination(s)"
        assert len(count) <= MIN_TRIED_NOTE_BUDGET
        with pytest.raises(ValueError, match="below"):
            tried_note(owner, budget=MIN_TRIED_NOTE_BUDGET - 1)

    def test_released_notes_keep_the_slots_first(self) -> None:
        assert released_note("shares=1+2", (_share(1, 2),)) == (
            "shares=1+2; share 1 of generation 2")
        assert released_note("shares=2+3", ()) == "shares=2+3"

    def test_a_mapping_is_the_v1_x_call_shape_at_generation_0(self) -> None:
        rows = as_stored_shares({2: "2-ab", 4: "4-cd"})

        assert sorted((r.index, r.generation, r.data) for r in rows) == [
            (2, 0, "2-ab"), (4, 0, "4-cd")]
        assert as_stored_shares(rows) == rows

    def test_filled_slots_ignore_empty_values(self) -> None:
        rows = [_share(1, 0), _share(1, 2), _share(4, 1, "")]

        assert filled_slots(rows) == {1}

    def test_the_v1_1_slot_rules_are_unchanged(self) -> None:
        assert slot_share({1: "1-ab"}, 1) == ("1-ab", "")
        assert slot_share({1: "2-ab"}, 1) == ("", "malformed")
        assert slot_share({}, 1) == ("", "missing")
        assert admin_shares({2: "2-ab", 1: "1-cd", 4: "4-ef"}) == (
            (1, "1-cd", "4-ef"), "")
        assert admin_shares({2: "2-ab"}) == ((0, "", ""), "admin_share_missing")


class TestAttempts:
    def test_owner_attempts_follow_the_order_with_the_presented_shares(self) -> None:
        rows = [_share(1, 0), _share(1, 2), _share(1, 1)]

        attempts = owner_attempts(rows, 1, "2-aa", "3-bb")

        assert [(used[0].generation, shares[1:]) for used, shares in attempts] == [
            (1, ["2-aa", "3-bb"]), (2, ["2-aa", "3-bb"]), (0, ["2-aa", "3-bb"])]
        assert all(shares[0] == used[0].data for used, shares in attempts)

    def test_admin_attempts_and_slots(self) -> None:
        pair = (_share(2, 1), _share(4, 2))

        [(used, shares)] = admin_attempts([pair])

        assert used == pair and shares == [pair[0].data, pair[1].data]
        assert admin_slots(pair) == "2+4"

    def test_generation_0_admin_shares_keep_the_v1_1_rule(self) -> None:
        rows = [_share(4, 1), _share(2, 0), _share(1, 0), _share(4, 0)]

        used, problem = generation_0_admin_shares(rows)

        assert problem == ""
        assert [(r.index, r.generation) for r in used] == [(1, 0), (4, 0)]
        assert generation_0_admin_shares([_share(4, 1), _share(2, 0)]) == (
            (), "admin_share_missing")


class TestFirstMatch:
    def _attempts(self, *generations: int):
        return owner_attempts([_share(1, g) for g in generations], 9, "2-ab")

    def test_the_first_matching_attempt_wins_and_later_ones_are_not_tried(
        self,
    ) -> None:
        tried: list[str] = []

        def recover(shares: list[str]) -> str:
            tried.append(shares[0])
            return "key-" + shares[0]

        attempts = self._attempts(3, 2, 1)
        key, used, reason = first_match(
            attempts, recover, lambda key: key == "key-" + attempts[1][1][0])

        assert (key, reason) == ("key-" + attempts[1][1][0], "")
        assert used == attempts[1][0]
        assert tried == [attempts[0][1][0], attempts[1][1][0]]

    def test_no_match_is_a_mismatch_unless_nothing_recombined(self) -> None:
        attempts = self._attempts(2, 1)

        assert first_match(attempts, lambda shares: "k", lambda key: False) == (
            None, (), "commitment_mismatch")
        assert first_match(attempts, lambda shares: None, lambda key: True) == (
            None, (), "recovery_failed")
        assert first_match([], lambda shares: "k", lambda key: True) == (
            None, (), "recovery_failed")
