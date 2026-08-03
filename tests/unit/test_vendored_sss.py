"""The standard-SSS path must run from the vendored library (R-1).

PyPI ``secretsharing==0.2.6`` is Python-2-only: a fresh ``pip install`` on
py3 succeeds but ``import secretsharing`` dies with ``NameError: long``.
The repository therefore vendors the proven py3 tree at
``desktop.crypto._vendor.secretsharing`` — these tests pin three things:

  - provenance: the production entry points actually bind to the vendored
    module (not to whatever happens to sit in site-packages)
  - independence: the vendored tree declares no hidden ``six`` dependency
  - compatibility: fixed recovery vectors, shared with the remote
    participation portal, so both sides provably reconstruct the same key
    from the same ``"N-<hex>"`` shares
"""

from __future__ import annotations

import inspect
import re

from desktop.crypto.sss_recover import recover_key
from desktop.crypto.sss_split import split_key

SHARE_PATTERN = re.compile(r"^[1-4]-[0-9a-f]+$")

# Key with a leading zero byte: recovery must restore the full 64-hex form,
# not the shortened integer form.
VECTOR_KEY = "00" + "ab" * 31

# Generated once with the vendored module (split is random; recovery is
# deterministic). The same vectors are handed to the remote portal so the
# server-side library copy can prove byte-identical behavior.
VECTOR_SHARES = (
    "1-3539e360f94613234bb72fec2d3ffb7e832e409556b377bd6f0ab664f471075f",
    "2-69c81b1646e07a9aebc2b42caed44b515ab0d57f01bb43cf3269c11e3d366313",
    "3-9e5652cb947ae2128bce386d30689b2432336a68acc30fe0f5c8cbd785fbbec7",
    "4-d2e48a80e215498a2bd9bcadb1fceaf709b5ff5257cadbf2b927d690cec11a7b",
)


class TestVendoredProvenance:
    """Production entry points bind to the vendored tree."""

    def test_split_binds_to_vendored_module(self) -> None:
        import desktop.crypto.sss_split as mod

        assert mod.SecretSharer.__module__ == (
            "desktop.crypto._vendor.secretsharing.sharing"
        )

    def test_recover_binds_to_vendored_module(self) -> None:
        import desktop.crypto.sss_recover as mod

        assert mod.SecretSharer.__module__ == (
            "desktop.crypto._vendor.secretsharing.sharing"
        )

    def test_vendored_tree_has_no_six_dependency(self) -> None:
        """A `six` import would be a hidden dependency no requirements
        file declares — the vendor deviation removes it, and a future
        re-sync from upstream must not bring it back."""
        from desktop.crypto._vendor.secretsharing import sharing

        source = inspect.getsource(sharing)
        assert not re.search(
            r"^\s*(?:import six\b|from six\b)", source, re.MULTILINE
        )


class TestShareContract:
    """The `"N-<hex>"` transport format the portal relies on."""

    def test_split_produces_four_indexed_hex_shares(self) -> None:
        shares = split_key("ab" * 32)

        assert len(shares) == 4
        for index, share in enumerate(shares, start=1):
            assert SHARE_PATTERN.fullmatch(share), share
            assert share.startswith(f"{index}-")

    def test_all_pairs_recover_with_leading_zeros_preserved(self) -> None:
        shares = split_key(VECTOR_KEY)

        for i in range(4):
            for j in range(i + 1, 4):
                recovered = recover_key([shares[i], shares[j]])
                assert recovered == VECTOR_KEY


class TestFixedVectors:
    """Deterministic recovery from frozen shares.

    If the vendored code (or the portal's copy) ever drifts — different
    prime table, charset, or interpolation — these fail first.
    """

    def test_owner_plus_investigator_pair(self) -> None:
        recovered = recover_key([VECTOR_SHARES[0], VECTOR_SHARES[1]])
        assert recovered == VECTOR_KEY

    def test_system_plus_admin_pair(self) -> None:
        recovered = recover_key([VECTOR_SHARES[2], VECTOR_SHARES[3]])
        assert recovered == VECTOR_KEY

    def test_share_order_does_not_matter(self) -> None:
        recovered = recover_key([VECTOR_SHARES[3], VECTOR_SHARES[0]])
        assert recovered == VECTOR_KEY

    def test_three_shares_also_recover(self) -> None:
        recovered = recover_key(
            [VECTOR_SHARES[1], VECTOR_SHARES[2], VECTOR_SHARES[3]]
        )
        assert recovered == VECTOR_KEY
