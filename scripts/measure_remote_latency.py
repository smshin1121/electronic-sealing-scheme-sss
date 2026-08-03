"""Local remote-participation request-latency measurement.

Measures client-observed loopback time for two requests in the standard
recovery path against a compatible local evaluation portal, 10 runs by
default:

  A. subject_identity  POST /submit_key_part          identity verification +
                                                      realm session (setup)
  B. subject_submit    POST /key_part_upload_and_check owner share s1 upload  [TIMED]
  C. officer_login     POST /login + /totp-verify     second factor (setup)
  D. officer_combine   POST /case_key_mgt combine     SSS combination         [TIMED]

Reported segment: B + D. The HTTP automation excludes human think-time, while
the timer includes each POST and its response. A/C are session setup and are
reported separately. The subject share row is deleted between repetitions so
the local evaluation fixture can be reused; the officer share stays seeded.
Database bookkeeping is performed only outside the timed requests.

Dependencies: requests, pyotp, pymysql. Secrets via environment only:
  EVAL_PORTAL_OFFICER_PASSWORD, EVAL_PORTAL_OFFICER_TOTP_SECRET,
  EVAL_PORTAL_DB_PASSWORD

Never run against a production service or case database.

Usage example:
  python scripts/measure_remote_latency.py \
      --base-url http://127.0.0.1:5000 --runs 10 \
      --subject-name "Synthetic Subject" --birth-yymmdd 900101 --gender 1 \
      --rrn-front 19900101 --phone 010-0000-0000 --email subject@example.test \
      --share-file ./synthetic-s1.share --seal-id S-SYNTHETIC-001 --case-id 1 \
      --officer-user synthetic-officer --db-port 3307 \
      --out output/remote-latency
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("remote_latency")

_CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
_DEFAULT_TIMEOUT = 30.0


class MeasurementError(Exception):
    """A step failed; carries enough context to diagnose without secrets."""


@dataclass(frozen=True)
class SubjectIdentity:
    name: str
    birth_yymmdd: str  # YYMMDD (seize_main)
    gender: str  # RRN gender digit '1'-'4'
    rrn_front: str  # YYYYMMDD (submit_key_part)
    phone: str  # 010-XXXX-XXXX
    email: str


@dataclass(frozen=True)
class OfficerAccount:
    username: str
    password: str
    totp_secret: str


@dataclass(frozen=True)
class DbAccess:
    host: str
    port: int
    user: str
    password: str
    name: str


@dataclass(frozen=True)
class MeasureConfig:
    base_url: str
    runs: int
    out_dir: Path
    subject: SubjectIdentity
    officer: OfficerAccount
    db: DbAccess
    share_file: Path
    seal_id: str
    case_id: str
    expected_key_hex: str
    success_marker: str
    timeout: float


def _get_csrf(sess: requests.Session, url: str, timeout: float) -> str:
    resp = sess.get(url, timeout=timeout)
    if resp.status_code != 200:
        raise MeasurementError(f"GET {url} -> HTTP {resp.status_code}")
    match = _CSRF_RE.search(resp.text)
    if not match:
        raise MeasurementError(f"csrf_token not found on {url}")
    return match.group(1)


def _timed_post(
    sess: requests.Session,
    url: str,
    timeout: float,
    **kwargs,
) -> tuple[float, requests.Response]:
    start = time.perf_counter()
    resp = sess.post(url, timeout=timeout, allow_redirects=True, **kwargs)
    elapsed = time.perf_counter() - start
    return elapsed, resp


def _split_phone(phone: str) -> tuple[str, str, str]:
    digits = re.sub(r"\D", "", phone)
    if len(digits) != 11:
        raise MeasurementError(f"phone must have 11 digits, got {len(digits)}")
    return digits[:3], digits[3:7], digits[7:]


def subject_identity(sess: requests.Session, cfg: MeasureConfig) -> float:
    """A (setup): identity verification + realm session on /submit_key_part."""
    url = f"{cfg.base_url}/submit_key_part"
    csrf = _get_csrf(sess, url, cfg.timeout)
    phone1, phone2, phone3 = _split_phone(cfg.subject.phone)
    elapsed, resp = _timed_post(
        sess,
        url,
        cfg.timeout,
        data={
            "csrf_token": csrf,
            "_action": "submit",
            "name": cfg.subject.name,
            "rrn_front": cfg.subject.rrn_front,
            "rrn_gender": cfg.subject.gender,
            "phone1": phone1,
            "phone2": phone2,
            "phone3": phone3,
            "email": cfg.subject.email,
        },
    )
    if resp.status_code != 200:
        raise MeasurementError(f"subject_identity failed: HTTP {resp.status_code}")
    return elapsed


def subject_submit(sess: requests.Session, cfg: MeasureConfig) -> float:
    """C [TIMED]: owner share s1 upload on /key_part_upload_and_check."""
    url = f"{cfg.base_url}/key_part_upload_and_check"
    csrf = _get_csrf(sess, url, cfg.timeout)
    with open(cfg.share_file, "rb") as fh:
        elapsed, resp = _timed_post(
            sess,
            url,
            cfg.timeout,
            data={
                "csrf_token": csrf,
                "action": "upload",
                "seal_id": cfg.seal_id,
            },
            files={"files[]": (cfg.share_file.name, fh)},
        )
    if resp.status_code != 200:
        raise MeasurementError(f"subject_submit failed: HTTP {resp.status_code}")
    return elapsed


def officer_login(sess: requests.Session, cfg: MeasureConfig) -> float:
    """D (setup): password login + TOTP second factor (/totp-verify)."""
    try:
        import pyotp
    except ImportError as exc:  # pragma: no cover
        raise MeasurementError("pyotp is required for officer TOTP login") from exc

    login_url = f"{cfg.base_url}/login"
    csrf = _get_csrf(sess, login_url, cfg.timeout)
    t_login, resp = _timed_post(
        sess,
        login_url,
        cfg.timeout,
        data={
            "csrf_token": csrf,
            "username": cfg.officer.username,
            "password": cfg.officer.password,
        },
    )
    if resp.status_code != 200:
        raise MeasurementError(f"officer login failed: HTTP {resp.status_code}")

    totp_url = f"{cfg.base_url}/totp-verify"  # public-nonsecret-url
    csrf = _get_csrf(sess, totp_url, cfg.timeout)
    code = pyotp.TOTP(cfg.officer.totp_secret).now()
    t_totp, resp = _timed_post(
        sess,
        totp_url,
        cfg.timeout,
        data={"csrf_token": csrf, "otp": code, "submit": "확인"},
    )
    if resp.status_code != 200:
        raise MeasurementError(f"TOTP verify failed: HTTP {resp.status_code}")
    return t_login + t_totp


def officer_combine(
    sess: requests.Session, cfg: MeasureConfig, seized_file_id: str
) -> float:
    """E [TIMED]: SSS combination on /case_key_mgt (combine POST only).

    pick_case / pick_seized_key are UI navigation redirects and excluded
    from the reported segment.
    """
    url = f"{cfg.base_url}/case_key_mgt"
    csrf = _get_csrf(sess, url, cfg.timeout)

    for action, extra in (
        ("pick_case", {"case_id": cfg.case_id}),
        ("pick_seized_key", {"case_id": cfg.case_id,
                             "seized_file_id": seized_file_id}),
    ):
        _, resp = _timed_post(
            sess,
            url,
            cfg.timeout,
            data={"csrf_token": csrf, "action": action, **extra},
        )
        if resp.status_code != 200:
            raise MeasurementError(f"{action} failed: HTTP {resp.status_code}")
        match = _CSRF_RE.search(resp.text)
        csrf = match.group(1) if match else csrf

    elapsed, resp = _timed_post(
        sess,
        url,
        cfg.timeout,
        data={
            "csrf_token": csrf,
            "action": "combine",
            "case_id": cfg.case_id,
            "seized_file_id": seized_file_id,
            "recomb_reason": "synthetic latency measurement run",
        },
    )
    if resp.status_code != 200 or cfg.success_marker not in resp.text:
        raise MeasurementError(
            f"combine failed: HTTP {resp.status_code}, "
            f"marker {cfg.success_marker!r} not found"
        )
    return elapsed


def _db_conn(db: DbAccess):
    import pymysql
    return pymysql.connect(
        host=db.host, port=db.port, user=db.user, password=db.password,
        db=db.name, charset="utf8mb4", autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def db_cleanup_subject_share(cfg: MeasureConfig) -> None:
    """Pre-run (outside timed segments): drop the subject share row so the
    uq_seal_share unique constraint admits a fresh insert."""
    conn = _db_conn(cfg.db)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM key_part_uploaded_file_info "
                "WHERE seal_id=%s AND share_index=1",
                (cfg.seal_id,),
            )
    finally:
        conn.close()


def db_verify_recovered_key(cfg: MeasureConfig, expected_key_hex: str) -> bool:
    """Post-combine (outside timed segments): prove the portal reconstructed
    the ORIGINAL key, not merely a well-formed one.

    The portal never returns the key in machine-readable form; it records the
    key check value KCV = SHA-256(key)[:4] on the append-only recombination
    event. Comparing that against SHA-256(expected)[:4] is a cryptographic
    commitment check on the reconstruction.
    """
    import hashlib
    expected_kcv = hashlib.sha256(bytes.fromhex(expected_key_hex)).digest()[:4]
    conn = _db_conn(cfg.db)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key_kcv, success FROM key_recombination_event "
                "WHERE seal_id=%s ORDER BY id DESC LIMIT 1",
                (cfg.seal_id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()
    if not row or not row.get("success"):
        raise MeasurementError("no successful recombination event recorded")
    if row["key_kcv"] != expected_kcv:
        raise MeasurementError(
            "recovered key mismatch: KCV differs from the original key"
        )
    return True


def db_resolve_seized_file_id(cfg: MeasureConfig) -> str:
    """Post-submit (outside timed segments): id of the just-inserted row."""
    conn = _db_conn(cfg.db)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM key_part_uploaded_file_info "
                "WHERE seal_id=%s AND share_index=1 "
                "ORDER BY id DESC LIMIT 1",
                (cfg.seal_id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        raise MeasurementError("subject share row not found after upload")
    return str(row["id"])


def run_once(
    cfg: MeasureConfig,
    run_idx: int,
    subject_sess: requests.Session,
    officer_sess: requests.Session,
) -> dict:
    """One measured iteration on ALREADY-AUTHENTICATED sessions.

    Identity verification and officer login happen once for the persistent
    two-role session pair. The per-run measured segments are the share-upload
    POST and the combine POST only.
    """
    db_cleanup_subject_share(cfg)
    result = {
        "run": run_idx,
        "subject_submit_s": subject_submit(subject_sess, cfg),
    }
    seized_file_id = db_resolve_seized_file_id(cfg)
    result["officer_combine_s"] = officer_combine(
        officer_sess, cfg, seized_file_id
    )
    result["key_verified"] = db_verify_recovered_key(cfg, cfg.expected_key_hex)
    result["submit_plus_combine_s"] = (
        result["subject_submit_s"] + result["officer_combine_s"]
    )
    return result


def summarize(runs: list[dict]) -> dict:
    keys = [k for k in runs[0] if k not in ("run", "key_verified")]
    summary: dict = {"n": len(runs),
                     "all_keys_verified": all(r["key_verified"] for r in runs)}
    for key in keys:
        values = [r[key] for r in runs]
        summary[key] = {
            "mean": round(statistics.mean(values), 4),
            "std": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
            "min": round(min(values), 4),
            "max": round(max(values), 4),
        }
    return summary


def write_outputs(cfg: MeasureConfig, runs: list[dict], summary: dict) -> None:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    environment = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "base_url": cfg.base_url,
        "runs": cfg.runs,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "measured_segment": "client-observed loopback time for subject "
                            "share-upload POST + officer combine POST; "
                            "identity/login setup and DB bookkeeping excluded",
    }
    for name, payload in (
        ("raw_runs.json", runs),
        ("summary.json", summary),
        ("environment.json", environment),
    ):
        path = cfg.out_dir / name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        logger.info("wrote %s", path)


def build_config(args: argparse.Namespace) -> MeasureConfig:
    password = os.environ.get("EVAL_PORTAL_OFFICER_PASSWORD")
    totp_secret = os.environ.get("EVAL_PORTAL_OFFICER_TOTP_SECRET")
    db_password = os.environ.get("EVAL_PORTAL_DB_PASSWORD")
    if not password or not totp_secret or not db_password:
        raise MeasurementError(
            "EVAL_PORTAL_OFFICER_PASSWORD, "
            "EVAL_PORTAL_OFFICER_TOTP_SECRET and EVAL_PORTAL_DB_PASSWORD "
            "must be set in the environment (never passed as CLI arguments)"
        )
    share_file = Path(args.share_file)
    if not share_file.is_file():
        raise MeasurementError(f"share file not found: {share_file}")
    expected_key_path = Path(args.expected_key_file)
    if not expected_key_path.is_file():
        raise MeasurementError(f"expected-key file not found: {expected_key_path}")
    expected_key_hex = expected_key_path.read_text(encoding="ascii").strip()
    if len(expected_key_hex) != 64:
        raise MeasurementError("expected key must be 64 hex characters")
    return MeasureConfig(
        base_url=args.base_url.rstrip("/"),
        runs=args.runs,
        out_dir=Path(args.out),
        subject=SubjectIdentity(
            name=args.subject_name,
            birth_yymmdd=args.birth_yymmdd,
            gender=args.gender,
            rrn_front=args.rrn_front,
            phone=args.phone,
            email=args.email,
        ),
        officer=OfficerAccount(
            username=args.officer_user,
            password=password,
            totp_secret=totp_secret,
        ),
        db=DbAccess(
            host=args.db_host, port=args.db_port, user=args.db_user,
            password=db_password, name=args.db_name,
        ),
        share_file=share_file,
        seal_id=args.seal_id,
        case_id=args.case_id,
        expected_key_hex=expected_key_hex,
        success_marker=args.success_marker,
        timeout=args.timeout,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base-url", required=True,
                        help="local portal base URL (never production)")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--out", default="artifacts/performance/remote_latency")
    parser.add_argument("--subject-name", required=True)
    parser.add_argument("--birth-yymmdd", required=True, help="YYMMDD")
    parser.add_argument("--gender", required=True, help="RRN gender digit 1-4")
    parser.add_argument("--rrn-front", required=True, help="YYYYMMDD")
    parser.add_argument("--phone", required=True, help="010-XXXX-XXXX")
    parser.add_argument("--email", required=True)
    parser.add_argument("--share-file", required=True, help="s1 .share file")
    parser.add_argument("--seal-id", required=True)
    parser.add_argument("--expected-key-file", required=True,
                        help="file holding the original 64-hex key, for "
                             "KCV verification of each reconstruction")
    parser.add_argument("--case-id", required=True,
                        help="identifier of the synthetic evaluation case")
    parser.add_argument("--officer-user", required=True)
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=3307)
    parser.add_argument("--db-user", default="root")
    parser.add_argument("--db-name", default="users")
    parser.add_argument("--success-marker", default="키 결합이 완료",
                        help="substring proving combine success in response")
    parser.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    try:
        cfg = build_config(args)
    except MeasurementError as exc:
        logger.error("config error: %s", exc)
        return 2

    subject_sess = requests.Session()
    officer_sess = requests.Session()
    runs: list[dict] = []
    try:
        try:
            setup_identity_s = subject_identity(subject_sess, cfg)
            setup_login_s = officer_login(officer_sess, cfg)
        except (MeasurementError, requests.RequestException) as exc:
            logger.error("session setup failed: %s", exc)
            return 1
        logger.info("setup: identity %.3fs, login+totp %.3fs",
                    setup_identity_s, setup_login_s)

        for idx in range(1, cfg.runs + 1):
            try:
                result = run_once(cfg, idx, subject_sess, officer_sess)
            except (MeasurementError, requests.RequestException) as exc:
                logger.error("run %d failed: %s", idx, exc)
                return 1
            logger.info(
                "run %d: submit %.3fs + combine %.3fs = %.3fs (key verified: %s)",
                idx, result["subject_submit_s"], result["officer_combine_s"],
                result["submit_plus_combine_s"], result["key_verified"],
            )
            runs.append(result)
    finally:
        subject_sess.close()
        officer_sess.close()

    summary = summarize(runs)
    summary["setup_subject_identity_s"] = round(setup_identity_s, 4)
    summary["setup_officer_login_totp_s"] = round(setup_login_s, 4)
    write_outputs(cfg, runs, summary)
    logger.info(
        "submit+combine: mean %.3fs / std %.3fs (n=%d), all keys verified: %s",
        summary["submit_plus_combine_s"]["mean"],
        summary["submit_plus_combine_s"]["std"],
        summary["n"], summary["all_keys_verified"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
