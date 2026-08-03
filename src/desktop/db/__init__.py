"""Database package for the digital evidence electronic sealing system.

Provides SQLite-based local storage for seal records, key shares,
and certificates.
"""

from .sqlite_store import (
    create_case,
    delete_case,
    get_case_artifacts,
    get_case_detail,
    get_case_for_seal,
    get_case_for_unseal,
    get_case_history,
    get_key_share,
    get_resealable_cases,
    get_seal_record,
    get_sealable_cases,
    get_unsealable_cases,
    init_db,
    list_all_cases,
    save_certificate,
    save_key_shares,
    save_seal_bundle,
    save_seal_record,
    search_cases,
    update_case_meta,
)

__all__ = [
    "init_db",
    "save_key_shares",
    "save_seal_record",
    "save_seal_bundle",
    "save_certificate",
    "get_seal_record",
    "get_key_share",
    "list_all_cases",
    "get_case_detail",
    "get_case_artifacts",
    "get_case_history",
    "search_cases",
    "delete_case",
    "update_case_meta",
    "create_case",
    "get_case_for_seal",
    "get_case_for_unseal",
    "get_sealable_cases",
    "get_unsealable_cases",
    "get_resealable_cases",
]
