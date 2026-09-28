"""Sealing steps S4-S7 driven by the data of the seal wizard (stage E, E1).

The GUI seals only through :class:`desktop.seal_process.SealProcess`: after
its S1 (``SealProcess.run_s1``), :func:`run_seal_steps` maps the wizard data
to a :class:`~desktop.seal_process.SealConfig` and runs S4 (record and
policy signature), S5 (PDF, PAdES signature and TSA timestamp), S6 (key
split by mode, wrapped s3/s4) and S7 (save), naming the step that fails.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from .seal_process import SealConfig, SealProcess, SealResult


class SealStepError(RuntimeError):
    """A sealing step (S4-S7) failed; the steps after it did not run.

    Attributes:
        step: The failing step, ``"S4"`` to ``"S7"``.
        cause: The exception raised by that step.
    """

    def __init__(self, step: str, cause: Exception) -> None:
        super().__init__(f"{step}: {cause}")
        self.step = step
        self.cause = cause


# Progress messages sent when each step starts (the GUI maps them to i18n).
SEAL_STEP_MESSAGES: dict[str, str] = {
    "S4": "Building seal record",
    "S5": "Generating signed record artifacts",
    "S6": "Splitting AES key",
    "S7": "Saving seal record",
}


def seal_config_from_wizard(wizard_data: Mapping[str, Any]) -> SealConfig:
    """Map the data collected by the seal wizard (S1-S3) to a SealConfig.

    The nested dicts are copied, so later edits of the wizard data do not
    reach the configuration.
    """
    return SealConfig(
        source_file=wizard_data["source_file"],
        output_dir=wizard_data["output_dir"],
        chunk_size_bytes=wizard_data["chunk_size_gb"] * (1024 ** 3),
        case_number=wizard_data["case_number"],
        investigator=dict(wizard_data.get("investigator", {})),
        seizure=dict(wizard_data.get("seizure", {})),
        media=dict(wizard_data.get("media", {})),
        subject=dict(wizard_data.get("subject", {})),
        signature_lines=list(wizard_data.get("signature_lines", [])),
        seal_mode=wizard_data.get("seal_mode", "standard"),
        unlock_days=wizard_data.get("unlock_days", 10),
        seal_id=wizard_data.get("seal_id") or None,
    )


def run_seal_steps(
    process: SealProcess,
    wizard_data: Mapping[str, Any],
    *,
    on_step: Optional[Callable[[str, str], None]] = None,
) -> SealResult:
    """Run S4 to S7 on the data collected by the wizard (S1 already done).

    S4 builds the record and signs the policy, S5 renders, PAdES-signs and
    timestamps it, S6 splits the key by mode and wraps s3/s4, S7 saves.

    Args:
        process: The sealing process whose S1 has completed.
        wizard_data: Data collected by the wizard (see
            :func:`seal_config_from_wizard`).
        on_step: Called as ``(step, message)`` when a step starts and for
            each S5 status message.

    Returns:
        The saved seal.

    Raises:
        SealStepError: Naming the step that failed; later steps do not run
            and nothing is saved unless S7 completed.
    """

    def _notify(step: str, msg: str) -> None:
        if on_step:
            on_step(step, msg)

    steps: tuple[tuple[str, Callable[[], Any]], ...] = (
        ("S4", process.run_s4),
        ("S5", lambda: process.run_s5(status_cb=lambda m: _notify("S5", m))),
        ("S6", process.run_s6),
        ("S7", process.run_s7),
    )
    step = "S4"
    try:
        process.set_config(seal_config_from_wizard(wizard_data))
        result: Any = None
        for step, run in steps:
            _notify(step, SEAL_STEP_MESSAGES[step])
            result = run()
        return result
    except Exception as exc:
        raise SealStepError(step, exc) from exc
