"""Wires settings into concrete components. The API and CLI build exactly one of these."""

from __future__ import annotations

from dataclasses import dataclass

from strongbox.audit import AuditLog
from strongbox.auth.policy import PolicyEngine
from strongbox.auth.principal import PrincipalRegistry
from strongbox.auth.tokens import DevHs256Verifier, OidcVerifier, TokenVerifier
from strongbox.config import AuthMode, BlobBackendKind, KmsBackend, Settings
from strongbox.crypto.fips import assert_fips
from strongbox.crypto.kms import GcpKmsKeyProvider, KeyProvider, LocalKeyProvider
from strongbox.errors import ConfigurationError
from strongbox.services.blobs import BlobService
from strongbox.services.guard import Guard
from strongbox.services.keys import DataKeyManager, Sealer
from strongbox.services.records import RecordService
from strongbox.storage.blobstore import BlobBackend, GcsBlobBackend, LocalBlobBackend, S3BlobBackend
from strongbox.storage.database import Database


@dataclass
class Container:
    settings: Settings
    db: Database
    kms: KeyProvider
    backend: BlobBackend
    keys: DataKeyManager
    audit: AuditLog
    guard: Guard
    principals: PrincipalRegistry
    blobs: BlobService
    records: RecordService
    verifier: TokenVerifier
    delegation_verifier: TokenVerifier

    @classmethod
    def build(
        cls,
        settings: Settings,
        *,
        kms: KeyProvider | None = None,
        backend: BlobBackend | None = None,
        verifier: TokenVerifier | None = None,
        delegation_verifier: TokenVerifier | None = None,
        create_schema: bool = False,
    ) -> Container:
        if settings.require_fips:
            assert_fips()
        db = Database(settings.database_url, pool_size=settings.database_pool_size)
        if create_schema:
            db.create_all()
        kms = kms or _kms(settings)
        backend = backend or _backend(settings)
        keys = DataKeyManager(
            db,
            kms,
            rotation_seconds=settings.data_key_rotation_seconds,
            cache_ttl_seconds=settings.data_key_cache_ttl_seconds,
        )
        sealer = Sealer(keys)
        audit = AuditLog(db)
        guard = Guard(
            PolicyEngine(settings.export_controlled_categories),
            audit,
            conceal_denied=settings.conceal_denied_resources,
        )
        return cls(
            settings=settings,
            db=db,
            kms=kms,
            backend=backend,
            keys=keys,
            audit=audit,
            guard=guard,
            principals=PrincipalRegistry(db),
            blobs=BlobService(
                db,
                backend,
                kms,
                sealer,
                guard,
                chunk_size=settings.chunk_size,
                max_blob_bytes=settings.max_blob_bytes,
                max_metadata_bytes=settings.max_blob_metadata_bytes,
            ),
            records=RecordService(db, keys, sealer, guard, max_record_bytes=settings.max_record_bytes),
            verifier=verifier or build_verifier(settings, settings.jwt_audiences),
            delegation_verifier=delegation_verifier
            or build_verifier(settings, settings.delegation_audiences),
        )


def _kms(s: Settings) -> KeyProvider:
    if s.kms_backend is KmsBackend.GCP:
        if not s.kms_key_name:
            raise ConfigurationError("kms_key_name is required for the gcp KMS backend")
        return GcpKmsKeyProvider(s.kms_key_name)
    return LocalKeyProvider(s.local_keyring_path)


def _backend(s: Settings) -> BlobBackend:
    if s.blob_backend is BlobBackendKind.GCS:
        if not s.gcs_bucket:
            raise ConfigurationError("gcs_bucket is required for the gcs backend")
        return GcsBlobBackend(s.gcs_bucket, s.gcs_prefix)
    if s.blob_backend is BlobBackendKind.S3:
        if not s.s3_bucket:
            raise ConfigurationError("s3_bucket is required for the s3 backend")
        return S3BlobBackend(s.s3_bucket, s.s3_prefix, endpoint_url=s.s3_endpoint_url, region=s.s3_region)
    return LocalBlobBackend(s.blob_local_path)


def build_verifier(s: Settings, audiences: list[str]) -> TokenVerifier:
    if s.auth_mode is AuthMode.OIDC:
        return OidcVerifier(
            s.oidc_issuer,
            audiences,
            jwks_url=s.oidc_jwks_url,
            leeway=s.jwt_leeway_seconds,
            max_lifetime=s.max_token_lifetime_seconds,
        )
    if s.dev_jwt_secret is None:
        raise ConfigurationError("dev_jwt_secret is required in dev-hs256 mode")
    return DevHs256Verifier(
        s.dev_jwt_secret.get_secret_value(),
        audiences,
        leeway=s.jwt_leeway_seconds,
        max_lifetime=s.max_token_lifetime_seconds,
    )
