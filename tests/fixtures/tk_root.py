"""A Tk root for the stage E GUI tests.

Two properties of this test host are handled here:

* Tcl intermittently fails to read its own library files while a root is
  created ("couldn't read file .../tk8.6/ttk/utils.tcl: no such file or
  directory"), in varying tests and also before any stage E change. The
  creation is retried a few times; the error is re-raised if it persists.
* Roots of earlier tests may still be cyclic garbage. They are collected on
  the main thread before and after each test: if the collector ran on a
  worker thread instead (the seal wizard runs S4-S7 on one), deleting a Tcl
  interpreter there makes Tcl panic and aborts the whole run.
"""

from __future__ import annotations

import gc
import time
import tkinter as tk

_ATTEMPTS = 3
_RETRY_DELAY_S = 0.2


def new_test_root() -> tk.Tk:
    """Create a withdrawn Tk root (retrying transient Tcl start-up errors)."""
    gc.collect()
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            root = tk.Tk()
        except tk.TclError:
            if attempt == _ATTEMPTS:
                raise
            time.sleep(_RETRY_DELAY_S)
            continue
        root.withdraw()
        return root
    raise AssertionError("unreachable")


def destroy_test_root(root: tk.Tk) -> None:
    """Destroy the root and collect it on the main thread."""
    try:
        root.destroy()
    except tk.TclError:
        pass
    gc.collect()
