"""Main entry point for the digital evidence electronic sealing system.

Initializes the database, checks the local master key, and launches
the Tkinter GUI application.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure src/ is on sys.path so absolute imports work when run directly
_SRC_DIR = str(Path(__file__).resolve().parent.parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_LEVEL = logging.INFO


def _setup_logging() -> None:
    """Configure root logger with console output."""
    logging.basicConfig(
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _get_app_data_dir() -> Path:
    """Return the application data directory, creating it if needed."""
    base = Path.home() / ".enc_envelope"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _get_db_path() -> str:
    """Return the default SQLite database file path."""
    return str(_get_app_data_dir() / "seal_system.db")


def _get_master_key_path() -> str:
    """Return the default master key file path."""
    return str(_get_app_data_dir() / "master.key")


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def _init_database(db_path: str) -> None:
    """Create database tables if they do not exist."""
    from desktop.db import init_db

    init_db(db_path)


def _ensure_master_key(master_key_path: str) -> None:
    """Generate the local master key if it does not exist."""
    from desktop.crypto import init_master_key

    if not Path(master_key_path).exists():
        init_master_key(master_key_path)
        logging.getLogger(__name__).info(
            "Master key created: %s", master_key_path
        )
    else:
        logging.getLogger(__name__).info(
            "Master key ready: %s", master_key_path
        )

    # Crypto/KMS helpers resolve the active master key path via env var.
    os.environ["MASTER_KEY_PATH"] = master_key_path


def _enable_dpi_awareness() -> None:
    """Opt in to per-monitor DPI awareness on Windows.

    Must be called BEFORE the Tk root window is created so that tkinter
    renders crisply at 125~200% display scaling. Safe no-op on non-Windows
    platforms or if the call fails.
    """
    try:
        import ctypes

        try:
            # 1 = PROCESS_SYSTEM_DPI_AWARE (Windows 8.1+)
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            # Fallback for older Windows versions
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        # Non-Windows platform or ctypes unavailable — ignore
        pass


def _ensure_tsa_service() -> None:
    """Create TSA credentials and start the local TSA server."""
    from desktop.signature import ensure_tsa_server_running

    tsa_url, cert_path = ensure_tsa_server_running()
    logging.getLogger(__name__).info(
        "Local TSA ready: %s (cert=%s)", tsa_url, cert_path
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Application entry point."""
    _setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting digital evidence sealing system")

    db_path = _get_db_path()
    master_key_path = _get_master_key_path()

    try:
        _init_database(db_path)
        _ensure_master_key(master_key_path)
        _ensure_tsa_service()
    except Exception:
        logger.exception("Initialization failed")
        sys.exit(1)

    from desktop.gui import MainApp

    _enable_dpi_awareness()
    app = MainApp(db_path=db_path)
    logger.info("Launching GUI")
    app.run()
    logger.info("Program exited")


if __name__ == "__main__":
    main()
