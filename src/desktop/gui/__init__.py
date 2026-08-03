"""GUI package for the digital evidence electronic sealing system.

Provides Tkinter-based user interface components for seal, unseal,
and reseal processes.
"""

from .i18n import add_listener, get_lang, remove_listener, set_lang, t
from .app import MainApp
from .case_detail_dialog import ArtifactsWindow, CaseDetailDialog, HistoryWindow
from .case_manager import CaseManager
from .dashboard import Dashboard
from .progress_dialog import ProgressDialog
from .seal_wizard import SealWizard
from .signature_pad import EnhancedSignaturePad
from .step_indicator import StepIndicator
from .toast import ToastManager
from .widgets import FileSelector, LabeledEntry, SignaturePad

__all__ = [
    "t",
    "get_lang",
    "set_lang",
    "add_listener",
    "remove_listener",
    "MainApp",
    "Dashboard",
    "SealWizard",
    "StepIndicator",
    "ProgressDialog",
    "LabeledEntry",
    "FileSelector",
    "SignaturePad",
    "EnhancedSignaturePad",
    "ToastManager",
    "CaseManager",
    "CaseDetailDialog",
    "ArtifactsWindow",
    "HistoryWindow",
]
