"""Object store backends. They only ever see ciphertext.

* ``LocalBlobBackend`` - filesystem, for dev/test.
* ``GcsBlobBackend`` - Google Cloud Storage (bucket with CMEK, uniform access, public access prevention).
* ``S3BlobBackend`` - any S3-compatible endpoint that supports multipart upload (AWS S3 in GovCloud,
  MinIO, self-hosted Supabase Storage).
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from strongbox.errors import ConfigurationError, Conflict, NotFound

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
READ_CHUNK = 1024 * 1024


def _check_key(key: str) -> str:
    if not _KEY_RE.match(key):
        raise ValueError(f"invalid storage key {key!r}")
    return key


class BlobWriter(Protocol):
    def write(self, data: bytes) -> None: ...

    def commit(self) -> None: ...

    def abort(self) -> None: ...


class BlobBackend(Protocol):
    def open_writer(self, key: str) -> BlobWriter: ...

    def read(self, key: str) -> Iterator[bytes]: ...

    def delete(self, key: str) -> None: ...

    def exists(self, key: str) -> bool: ...

    def describe(self) -> dict[str, Any]: ...


# --------------------------------------------------------------------------------------------
class _LocalWriter:
    def __init__(self, final: Path) -> None:
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            raise Conflict("object already exists")
        self._final = final
        fd, tmp = tempfile.mkstemp(dir=final.parent, prefix=".upload-")
        self._tmp = Path(tmp)
        self._fh = os.fdopen(fd, "wb")

    def write(self, data: bytes) -> None:
        self._fh.write(data)

    def commit(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        os.chmod(self._tmp, 0o600)
        os.replace(self._tmp, self._final)

    def abort(self) -> None:
        if not self._fh.closed:
            self._fh.close()
        self._tmp.unlink(missing_ok=True)


class LocalBlobBackend:
    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        _check_key(key)
        return self._root / key[-2:] / key

    def open_writer(self, key: str) -> BlobWriter:
        return _LocalWriter(self._path(key))

    def read(self, key: str) -> Iterator[bytes]:
        path = self._path(key)
        if not path.exists():
            raise NotFound("object missing from blob store")
        with path.open("rb") as fh:
            while chunk := fh.read(READ_CHUNK):
                yield chunk

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def describe(self) -> dict[str, Any]:
        return {"backend": "local", "root": str(self._root), "production_safe": False}


# --------------------------------------------------------------------------------------------
class _GcsWriter:
    def __init__(self, blob: Any) -> None:
        self._blob = blob
        # if_generation_match=0: never overwrite an existing object.
        self._fh = blob.open("wb", chunk_size=8 * 1024 * 1024, if_generation_match=0)

    def write(self, data: bytes) -> None:
        self._fh.write(data)

    def commit(self) -> None:
        self._fh.close()

    def abort(self) -> None:
        try:
            self._fh.close()
        finally:
            # Best-effort cleanup; `strongbox gc` sweeps anything left behind.
            with contextlib.suppress(Exception):
                self._blob.delete()


class GcsBlobBackend:
    def __init__(self, bucket_name: str, prefix: str = "objects/", bucket: Any | None = None) -> None:
        if bucket is None:
            try:
                from google.cloud import storage  # type: ignore[attr-defined,unused-ignore]
            except ImportError as exc:  # pragma: no cover
                raise ConfigurationError("install strongbox[gcp] to use GCS") from exc
            bucket = storage.Client().bucket(bucket_name)
        self._bucket = bucket
        self._name = bucket_name
        self._prefix = prefix

    def _blob(self, key: str) -> Any:
        return self._bucket.blob(self._prefix + _check_key(key))

    def open_writer(self, key: str) -> BlobWriter:
        return _GcsWriter(self._blob(key))

    def read(self, key: str) -> Iterator[bytes]:
        blob = self._blob(key)
        if not blob.exists():
            raise NotFound("object missing from blob store")
        with blob.open("rb", chunk_size=READ_CHUNK) as fh:
            while chunk := fh.read(READ_CHUNK):
                yield chunk

    def delete(self, key: str) -> None:
        blob = self._blob(key)
        if blob.exists():
            blob.delete()

    def exists(self, key: str) -> bool:
        return bool(self._blob(key).exists())

    def describe(self) -> dict[str, Any]:
        return {"backend": "gcs", "bucket": self._name, "prefix": self._prefix, "production_safe": True}


# --------------------------------------------------------------------------------------------
_S3_PART = 8 * 1024 * 1024  # S3 requires >= 5 MiB for every part but the last


class _S3Writer:
    def __init__(self, client: Any, bucket: str, key: str) -> None:
        self._c, self._bucket, self._key = client, bucket, key
        self._buf = bytearray()
        self._upload_id: str | None = None
        self._parts: list[dict[str, Any]] = []

    def _flush_part(self) -> None:
        if self._upload_id is None:
            resp = self._c.create_multipart_upload(Bucket=self._bucket, Key=self._key)
            self._upload_id = resp["UploadId"]
        number = len(self._parts) + 1
        body = bytes(self._buf[:_S3_PART])
        del self._buf[:_S3_PART]
        resp = self._c.upload_part(
            Bucket=self._bucket, Key=self._key, UploadId=self._upload_id, PartNumber=number, Body=body
        )
        self._parts.append({"PartNumber": number, "ETag": resp["ETag"]})

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) > _S3_PART:
            self._flush_part()

    def commit(self) -> None:
        if self._upload_id is None:
            self._c.put_object(Bucket=self._bucket, Key=self._key, Body=bytes(self._buf))
            return
        if self._buf:
            self._flush_part()
        self._c.complete_multipart_upload(
            Bucket=self._bucket,
            Key=self._key,
            UploadId=self._upload_id,
            MultipartUpload={"Parts": self._parts},
        )

    def abort(self) -> None:
        if self._upload_id is not None:
            self._c.abort_multipart_upload(Bucket=self._bucket, Key=self._key, UploadId=self._upload_id)


class S3BlobBackend:
    def __init__(
        self,
        bucket: str,
        prefix: str = "objects/",
        *,
        endpoint_url: str | None = None,
        region: str | None = None,
        client: Any | None = None,
    ) -> None:
        if client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover
                raise ConfigurationError("install strongbox[s3] to use an S3-compatible store") from exc
            client = boto3.client("s3", endpoint_url=endpoint_url, region_name=region)
        self._c = client
        self._bucket = bucket
        self._prefix = prefix
        self._endpoint = endpoint_url

    def _key(self, key: str) -> str:
        return self._prefix + _check_key(key)

    def open_writer(self, key: str) -> BlobWriter:
        return _S3Writer(self._c, self._bucket, self._key(key))

    def read(self, key: str) -> Iterator[bytes]:
        try:
            resp = self._c.get_object(Bucket=self._bucket, Key=self._key(key))
        except Exception as exc:
            if "NoSuchKey" in type(exc).__name__ or "NoSuchKey" in str(exc):
                raise NotFound("object missing from blob store") from exc
            raise
        body = resp["Body"]
        yield from body.iter_chunks(chunk_size=READ_CHUNK)

    def delete(self, key: str) -> None:
        self._c.delete_object(Bucket=self._bucket, Key=self._key(key))

    def exists(self, key: str) -> bool:
        try:
            self._c.head_object(Bucket=self._bucket, Key=self._key(key))
            return True
        except Exception:  # noqa: BLE001
            return False

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "s3",
            "bucket": self._bucket,
            "endpoint": self._endpoint or "aws",
            "production_safe": True,
        }
