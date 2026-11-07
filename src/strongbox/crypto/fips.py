"""Runtime check that the crypto module is operating in FIPS mode.

AES-256-GCM, HMAC-SHA-256 and SHA-256 are FIPS-approved algorithms, but CUI requires a
FIPS-*validated* module (NIST SP 800-171 3.13.11). ``cryptography`` delegates to OpenSSL, so
validation depends on the OpenSSL build in the container image: run on a base image whose
OpenSSL FIPS provider holds a CMVP certificate and is active, and set STRONGBOX_REQUIRE_FIPS=true.
Key wrapping happens in Cloud KMS HSMs, which are validated separately.
"""

from __future__ import annotations

from typing import Any

from strongbox.errors import ConfigurationError


def fips_status() -> dict[str, Any]:
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.bindings._rust import openssl as rust_openssl

    return {"openssl": backend.openssl_version_text(), "fips_enabled": bool(rust_openssl.is_fips_enabled())}


def assert_fips() -> None:
    status = fips_status()
    if not status["fips_enabled"]:
        raise ConfigurationError(
            f"FIPS mode is required but not active ({status['openssl']}). "
            "Use a FIPS-enabled base image or unset STRONGBOX_REQUIRE_FIPS outside production."
        )
