"""The format check of uploaded shares (stage F, F1; web.share_upload).

A share is stripped and lower-cased; it must be ``<slot>-<hex digits>``
with the upload route's own slot, and at most 4096 characters (the share
file bound of the sync contract, section 5). Anything else is refused
with 400 and a Korean message that never repeats the value.
"""

from __future__ import annotations

import pytest

from web.share_upload import MAX_SHARE_LENGTH, checked_share


@pytest.mark.parametrize("slot", [1, 2])
def test_a_share_is_stripped_and_lower_cased(slot: int) -> None:
    share, refusal = checked_share(f"  {slot}-ABcd09\r\n", slot)

    assert (share, refusal) == (f"{slot}-abcd09", None)


@pytest.mark.parametrize("slot", [1, 2])
@pytest.mark.parametrize("raw", [
    "{other}-abcd",       # another slot's share
    "{slot}-",            # no digits
    "{slot}-xyz0",        # not hex
    "{slot}-ab cd",       # inner whitespace
    "abcd",               # no index
    "{slot}{slot}-abcd",  # index 11 or 22
    "１-abcd",        # a full-width digit is not an index
    "-abcd",
])
def test_malformed_shares_are_refused_with_400(slot: int, raw: str) -> None:
    other = 2 if slot == 1 else 1
    value = raw.format(slot=slot, other=other)

    share, refusal = checked_share(value, slot)

    assert share == ""
    assert refusal is not None and refusal.status == 400
    assert "키 조각" in refusal.message
    assert "abcd" not in refusal.message and "xyz0" not in refusal.message


def test_the_length_bound_is_4096_characters() -> None:
    longest = "1-" + "a" * (MAX_SHARE_LENGTH - 2)

    assert MAX_SHARE_LENGTH == 4096
    assert checked_share(longest, 1) == (longest, None)
    share, refusal = checked_share(longest + "a", 1)
    assert share == "" and refusal is not None and refusal.status == 400
