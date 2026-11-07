from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from strongbox.auth.tokens import DevHs256Verifier, OidcVerifier, mint_dev_token
from strongbox.config import Settings
from strongbox.errors import Unauthenticated

ISS = "https://accounts.google.com"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _google_token(**overrides: Any) -> str:
    now = int(time.time())
    claims = {
        "iss": ISS,
        "aud": "https://strongbox.internal",
        "sub": "1234567890",
        "email": "svc-mes@proj.iam.gserviceaccount.com",
        "email_verified": True,
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})


def _verifier() -> OidcVerifier:
    return OidcVerifier(ISS, ["https://strongbox.internal"], key_resolver=lambda _t: KEY.public_key())


def test_google_id_token_maps_to_email() -> None:
    assert _verifier().verify(_google_token()).subject == "svc-mes@proj.iam.gserviceaccount.com"


def test_unverified_email_falls_back_to_sub() -> None:
    assert _verifier().verify(_google_token(email_verified=False)).subject == "1234567890"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "https://other"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
        {"iat": int(time.time()), "exp": int(time.time()) + 10 * 86400},  # lifetime over policy
    ],
)
def test_rejections(overrides: dict[str, Any]) -> None:
    with pytest.raises(Unauthenticated):
        _verifier().verify(_google_token(**overrides))


def test_wrong_signing_key() -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = jwt.encode(
        {"iss": ISS, "aud": "https://strongbox.internal", "sub": "x", "iat": 1, "exp": 2**31}, other, "RS256"
    )
    with pytest.raises(Unauthenticated):
        _verifier().verify(tok)


def test_hs256_alg_confusion_rejected_by_oidc() -> None:
    tok = jwt.encode({"iss": ISS, "aud": "https://strongbox.internal", "sub": "x"}, "secret" * 8, "HS256")
    with pytest.raises(Unauthenticated):
        _verifier().verify(tok)


def test_dev_tokens() -> None:
    secret = "s" * 40
    v = DevHs256Verifier(secret, ["strongbox"])
    assert v.verify(mint_dev_token(secret, "alice")).subject == "alice"
    with pytest.raises(Unauthenticated):
        v.verify(mint_dev_token("t" * 40, "alice"))


def test_production_guards() -> None:
    with pytest.raises(ValueError, match="refusing to start in production"):
        Settings(_env_file=None, env="production", dev_jwt_secret="x" * 40)  # type: ignore[call-arg]
    ok = Settings(
        _env_file=None,  # type: ignore[call-arg]
        env="production",
        auth_mode="oidc",
        kms_backend="gcp",
        kms_key_name="projects/p/locations/us-east4/keyRings/r/cryptoKeys/k",
        blob_backend="gcs",
        gcs_bucket="b",
        database_url="postgresql+psycopg://u@h/db",
        require_fips=True,
        expose_docs=False,
    )
    assert ok.env.value == "production"


def test_short_dev_secret_rejected() -> None:
    with pytest.raises(ValueError, match="DEV_JWT_SECRET"):
        Settings(_env_file=None, dev_jwt_secret="short")  # type: ignore[call-arg]
