# Vendored: secretsharing (Shamir's Secret Sharing)

- **Upstream**: `secret-sharing` by Halfmoon Labs / Blockstack (MIT — see `LICENSE`)
- **This tree**: the Python-3-compatible sources carrying `__version__ = '0.2.7'`
  (upstream master; never released to PyPI), four modules only:
  `__init__.py`, `sharing.py`, `polynomials.py`, `primes.py`
- **Vendored**: 2026-08-02

## Why this is vendored

The latest PyPI release (`secretsharing==0.2.6`, 2015) is **Python-2-only**: installing
it on Python 3 succeeds, but `import secretsharing` fails immediately with
`NameError: name 'long' is not defined` (`primes.py` executes
`calculate_mersenne_primes()` at module load). A working installation therefore cannot
be reproduced with `pip install` alone, which breaks reviewer reproducibility of the
public repository. Vendoring the proven py3 sources closes that gap.

Runtime dependency `utilitybelt==0.2.6` stays on pip — its PyPI release works on
Python 3 (verified: import and `secure_randint`).

## Deviation from upstream (exactly one)

`sharing.py`: `from six import integer_types` → `integer_types = (int,)`.
Upstream used `six` for py2/py3 dual support; this tree is py3-only, and keeping the
import would add a hidden `six` dependency that no requirements file declares.

## Do not re-sync from PyPI

`pip install secretsharing` would reintroduce the broken py2 code. Any update must
preserve share-format compatibility: shares are `"N-<hex>"` strings exchanged with the
remote participation portal, and both sides must recover identical secrets.
`tests/unit/test_vendored_sss.py` pins fixed recovery vectors for this contract.
