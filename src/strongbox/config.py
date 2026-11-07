"""Runtime configuration (env vars prefixed STRONGBOX_). Production mode refuses unsafe settings."""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    PRODUCTION = "production"


class KmsBackend(StrEnum):
    LOCAL = "local"
    GCP = "gcp"


class BlobBackendKind(StrEnum):
    LOCAL = "local"
    GCS = "gcs"
    S3 = "s3"


class AuthMode(StrEnum):
    DEV_HS256 = "dev-hs256"
    OIDC = "oidc"


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="STRONGBOX_", env_file=".env", extra="ignore")

    env: Environment = Environment.DEV

    # Structured store. Any SQLAlchemy URL; Postgres (Cloud SQL, AlloyDB, self-hosted Supabase) in production.
    database_url: str = "sqlite:///./.strongbox/strongbox.db"
    database_pool_size: int = 10

    # Key management. Production must use Cloud KMS (HSM protection level).
    kms_backend: KmsBackend = KmsBackend.LOCAL
    kms_key_name: str | None = None
    local_keyring_path: Path = Path(".strongbox/keyring.json")

    # Blob store backends.
    blob_backend: BlobBackendKind = BlobBackendKind.LOCAL
    blob_local_path: Path = Path(".strongbox/blobs")
    gcs_bucket: str | None = None
    gcs_prefix: str = "objects/"
    s3_bucket: str | None = None
    s3_prefix: str = "objects/"
    s3_endpoint_url: str | None = None
    s3_region: str | None = None

    max_blob_bytes: int = 5 * GIB
    chunk_size: int = 64 * KIB
    max_record_bytes: int = 1 * MIB
    max_blob_metadata_bytes: int = 16 * KIB

    # Data keys (records and sealed metadata). Rotation bounds how much data any one DEK protects.
    data_key_rotation_seconds: int = 7 * 24 * 3600
    data_key_cache_ttl_seconds: int = 300

    # Authentication.
    auth_mode: AuthMode = AuthMode.DEV_HS256
    dev_jwt_secret: SecretStr | None = None
    jwt_audiences: list[str] = Field(default_factory=lambda: ["strongbox"])
    delegation_audiences: list[str] = Field(default_factory=lambda: ["strongbox"])
    oidc_issuer: str = "https://accounts.google.com"
    oidc_jwks_url: str = "https://www.googleapis.com/oauth2/v3/certs"
    jwt_leeway_seconds: int = 30
    max_token_lifetime_seconds: int = 24 * 3600

    # Policy.
    export_controlled_categories: list[str] = Field(
        default_factory=lambda: ["SP-EXPT", "EXPT", "SP-EXPTR", "EXPTR"]
    )
    conceal_denied_resources: bool = True

    # Crypto module. CUI requires FIPS-validated cryptography (NIST SP 800-171 3.13.11).
    require_fips: bool = False

    # API surface.
    expose_docs: bool = True
    log_level: str = "INFO"

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if not 4 * KIB <= self.chunk_size <= 4 * MIB:
            raise ValueError("chunk_size must be between 4 KiB and 4 MiB")
        if self.kms_backend is KmsBackend.GCP and not self.kms_key_name:
            raise ValueError("STRONGBOX_KMS_KEY_NAME is required when kms_backend=gcp")
        if self.blob_backend is BlobBackendKind.GCS and not self.gcs_bucket:
            raise ValueError("STRONGBOX_GCS_BUCKET is required when blob_backend=gcs")
        if self.blob_backend is BlobBackendKind.S3 and not self.s3_bucket:
            raise ValueError("STRONGBOX_S3_BUCKET is required when blob_backend=s3")
        if self.auth_mode is AuthMode.DEV_HS256:
            secret = self.dev_jwt_secret.get_secret_value() if self.dev_jwt_secret else ""
            if len(secret) < 32:
                raise ValueError("STRONGBOX_DEV_JWT_SECRET must be at least 32 characters in dev-hs256 mode")

        if self.env is Environment.PRODUCTION:
            problems = []
            if self.kms_backend is KmsBackend.LOCAL:
                problems.append("kms_backend=local (use gcp with an HSM-protected key)")
            if self.auth_mode is AuthMode.DEV_HS256:
                problems.append("auth_mode=dev-hs256 (use oidc)")
            if self.database_url.startswith("sqlite"):
                problems.append("database_url is SQLite (use Postgres)")
            if self.blob_backend is BlobBackendKind.LOCAL:
                problems.append("blob_backend=local (use gcs or s3)")
            if not self.require_fips:
                problems.append("require_fips=false (CUI requires FIPS-validated crypto)")
            if self.expose_docs:
                problems.append("expose_docs=true")
            if problems:
                raise ValueError("refusing to start in production: " + "; ".join(problems))
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
