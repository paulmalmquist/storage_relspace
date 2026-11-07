"""Bearer token verification.

* ``OidcVerifier`` - production. Verifies RS256/ES256 JWTs against the issuer's JWKS. With the
  defaults it accepts Google-signed ID tokens, which is how Cloud Run services, GKE workloads
  (Workload Identity) and users behind IAP authenticate to each other without shared secrets.
* ``DevHs256Verifier`` - local development with a shared secret. Production mode refuses it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import jwt

from strongbox.errors import Unauthenticated

DEV_ISSUER = "strongbox-dev"


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    subject: str
    issuer: str
    audience: str | list[str]
    expires_at: int
    claims: dict[str, Any]


class TokenVerifier(Protocol):
    def verify(self, token: str) -> VerifiedToken: ...


def _check_lifetime(claims: dict[str, Any], max_lifetime: int) -> None:
    iat = claims.get("iat")
    if iat is not None and int(claims["exp"]) - int(iat) > max_lifetime:
        raise Unauthenticated("token lifetime exceeds policy")


class DevHs256Verifier:
    def __init__(
        self, secret: str, audiences: Sequence[str], *, leeway: int = 30, max_lifetime: int = 86400
    ) -> None:
        self._secret = secret
        self._aud = list(audiences)
        self._leeway = leeway
        self._max = max_lifetime

    def verify(self, token: str) -> VerifiedToken:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                audience=self._aud,
                issuer=DEV_ISSUER,
                leeway=self._leeway,
                options={"require": ["exp", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise Unauthenticated(f"invalid token: {exc}") from exc
        _check_lifetime(claims, self._max)
        return VerifiedToken(claims["sub"], claims["iss"], claims["aud"], int(claims["exp"]), claims)


def mint_dev_token(secret: str, subject: str, audience: str = "strongbox", ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": subject, "aud": audience, "iss": DEV_ISSUER, "iat": now, "exp": now + ttl_seconds},
        secret,
        algorithm="HS256",
    )


class OidcVerifier:
    """Verifies OIDC ID tokens. The principal subject is the verified email when present (Google service
    accounts and users), otherwise ``sub``."""

    def __init__(
        self,
        issuer: str,
        audiences: Sequence[str],
        *,
        jwks_url: str | None = None,
        key_resolver: Callable[[str], Any] | None = None,
        leeway: int = 30,
        max_lifetime: int = 86400,
    ) -> None:
        self._issuer = issuer
        self._aud = list(audiences)
        self._leeway = leeway
        self._max = max_lifetime
        if key_resolver is None:
            if not jwks_url:
                raise ValueError("jwks_url or key_resolver is required")
            client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
            key_resolver = lambda tok: client.get_signing_key_from_jwt(tok).key  # noqa: E731
        self._resolve = key_resolver

    def verify(self, token: str) -> VerifiedToken:
        try:
            key = self._resolve(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256", "ES256"],
                audience=self._aud,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise Unauthenticated(f"invalid token: {exc}") from exc
        _check_lifetime(claims, self._max)
        subject = claims["sub"]
        if claims.get("email") and claims.get("email_verified") is True:
            subject = claims["email"]
        return VerifiedToken(subject, claims["iss"], claims["aud"], int(claims["exp"]), claims)
