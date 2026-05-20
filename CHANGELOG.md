# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Security

- **[CRITICAL] Fixed silent SHA-512 → SHA-384 mismatch in `hashes.py`**
  The `sha512` branch of `HashFunction.__call__` was calling `hash_sha384()` instead
  of `hash_sha512()`. Any signature produced with `--hash-algorithm sha512` carried a
  SHA-384 digest under the SHA-512 DER OID, making it cryptographically invalid and
  unverifiable by any conformant verifier. The fix is a single-line correction.

- **[HIGH] Added PIN length validation before card transmission in `commands/general.py`**
  The PIN was sent to the DNIe card without any length or content validation.
  An empty or malformed PIN would waste retry attempts and risk permanently locking
  the card (typically 3–5 failed attempts triggers a block). Added a 4–16 character
  length check before encoding.

- **[HIGH] Secure PIN zeroing in `commands/general.py`**
  The PIN was stored as an immutable Python `str` and a `bytes` object, neither of
  which can be securely erased. Changed to `bytearray` and zero all bytes in a
  `finally` block immediately after the APDU transmission.

- **[MEDIUM] Added input file size limit in `commands/signature.py`**
  `input_file.read_bytes()` had no upper bound, allowing a multi-gigabyte file to
  exhaust system memory. Added a 512 MB hard limit that raises a `ValueError` before
  reading.

- **[MEDIUM] Atomic output file writes in `commands/signature.py` and `commands/certificate.py`**
  Output files were written with `Path.write_bytes()`, which silently overwrites the
  target and leaves a corrupt file if interrupted mid-write. Changed to write to a
  `.tmp` sibling file first and rename atomically with `os.replace()`.

- **[MEDIUM] Fixed broken f-string and replaced `print()` with `logging` in `commands/certificate.py`**
  The first debug line used `"Select PKI: '{r:!r}'"` (string literal, not an f-string),
  so it always printed the literal text instead of the APDU response. All `print()`
  debug calls replaced with `logging.debug()` to avoid leaking raw APDU data to stdout.

- **[MEDIUM] Moved TLV tag validation before data accumulation in `commands/certificate.py`**
  The `r.data[0] != 0x53` check was performed *after* appending the chunk to the
  output buffer, meaning a malformed or malicious response would be partially
  accumulated before the error was raised. Validation now occurs before accumulation.

- **[MEDIUM] Added `lc > 255` validation in `APDUCommand.__attrs_post_init__`**
  Serializing an `APDUCommand` with `lc > 255` would raise an unhandled `OverflowError`
  at serialization time. Added an explicit check in `__attrs_post_init__` that raises
  a descriptive `ValueError` early.

- **[LOW] Fixed `PERUDNIE_LANG` environment variable validation in `i18n.py`**
  An unsupported language code (e.g. `PERUDNIE_LANG=fr`) was used directly as a
  dict key, causing an uncaught `KeyError` crash at import time before any error
  handling could run. Added a guard: the value is only applied if it is one of the
  supported codes (`en`, `es`).

- **[MEDIUM] Replaced PyPI username/password with OIDC Trusted Publishing in `release.yaml`**
  The CI workflow used `TWINE_USERNAME` / `TWINE_PASSWORD` secrets to publish to PyPI.
  PyPI has deprecated password-based uploads, and a leaked password would compromise
  the entire PyPI account. Replaced with `pypa/gh-action-pypi-publish` using OIDC
  Trusted Publishing, which requires no stored credentials.
  **Action required:** configure a Trusted Publisher on PyPI for this repository and
  the `release.yaml` workflow.
