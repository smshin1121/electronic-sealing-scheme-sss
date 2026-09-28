"""Identity protection for the reference web app (stage E, E3a).

The subject's identity is never stored in plaintext:

  - name, birth date and phone are matched by keyed digests
    (:mod:`web.privacy.digests`: HMAC-SHA256 under a server pepper,
    separated by field and bound to the seal ID);
  - name and e-mail are kept for authorised use as AES-256-GCM ciphertexts
    under a per-seal data key, which is stored only wrapped by the privacy
    master key (:mod:`web.privacy.field_crypto`);
  - every decryption is audited, and a value is not returned when its
    audit row cannot be written (:mod:`web.privacy.case_identity`).

The keys are configured by path (:mod:`web.privacy.keys`). Unset or
unusable keys refuse to start the app; a key file that becomes unreadable
later refuses identity writes and checks at request time (HTTP 503).
Existing ``cases`` rows are converted by ``python -m src.web.privacy.migrate``
(see that module).

E3b stores the synced seal records (``seal_records.record_json`` and
``record_pdf``) encrypted under the same per-seal data keys, bound to the
seal, the event and the column (:mod:`web.privacy.record_crypto`,
:mod:`web.privacy.record_store`); a person sees a record only through
:mod:`web.privacy.record_access`, which audits every decryption. The same
command converts existing records (:mod:`web.privacy.record_migration`).
"""
