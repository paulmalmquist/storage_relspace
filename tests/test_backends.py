"""Object-store backends against in-memory fakes of the GCS and S3 client surfaces they use."""

from __future__ import annotations

import io
import os
from typing import Any

import pytest

from strongbox.errors import NotFound
from strongbox.storage.blobstore import GcsBlobBackend, LocalBlobBackend, S3BlobBackend


class _FakeGcsWriter(io.BytesIO):
    def __init__(self, store: dict[str, bytes], name: str) -> None:
        super().__init__()
        self._store, self._name = store, name

    def close(self) -> None:
        if not self.closed:
            self._store[self._name] = self.getvalue()
        super().close()


class _FakeGcsBlob:
    def __init__(self, store: dict[str, bytes], name: str) -> None:
        self._store, self.name = store, name

    def open(self, mode: str, **kw: Any) -> Any:
        if mode == "wb":
            assert kw.get("if_generation_match") == 0
            return _FakeGcsWriter(self._store, self.name)
        return io.BytesIO(self._store[self.name])

    def exists(self) -> bool:
        return self.name in self._store

    def delete(self) -> None:
        self._store.pop(self.name, None)


class _FakeBucket:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def blob(self, name: str) -> _FakeGcsBlob:
        return _FakeGcsBlob(self.store, name)


class _Body:
    def __init__(self, data: bytes) -> None:
        self._d = data

    def iter_chunks(self, chunk_size: int) -> Any:
        for i in range(0, len(self._d), chunk_size):
            yield self._d[i : i + chunk_size]


class _FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, dict[int, bytes]] = {}

    def put_object(self, Bucket: str, Key: str, Body: bytes) -> None:
        self.objects[Key] = Body

    def create_multipart_upload(self, Bucket: str, Key: str) -> dict[str, str]:
        self.uploads["u1"] = {}
        return {"UploadId": "u1"}

    def upload_part(
        self, Bucket: str, Key: str, UploadId: str, PartNumber: int, Body: bytes
    ) -> dict[str, str]:
        self.uploads[UploadId][PartNumber] = Body
        return {"ETag": f"e{PartNumber}"}

    def complete_multipart_upload(
        self, Bucket: str, Key: str, UploadId: str, MultipartUpload: dict[str, Any]
    ) -> None:
        parts = self.uploads.pop(UploadId)
        self.objects[Key] = b"".join(parts[p["PartNumber"]] for p in MultipartUpload["Parts"])

    def abort_multipart_upload(self, Bucket: str, Key: str, UploadId: str) -> None:
        self.uploads.pop(UploadId, None)

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
        if Key not in self.objects:
            raise KeyError("NoSuchKey")
        return {"Body": _Body(self.objects[Key])}

    def delete_object(self, Bucket: str, Key: str) -> None:
        self.objects.pop(Key, None)

    def head_object(self, Bucket: str, Key: str) -> None:
        if Key not in self.objects:
            raise KeyError("404")


def _exercise(backend: Any, size: int) -> None:
    data = os.urandom(size)
    w = backend.open_writer("obj_1")
    for i in range(0, len(data), 1_000_000):
        w.write(data[i : i + 1_000_000])
    w.commit()
    assert backend.exists("obj_1")
    assert b"".join(backend.read("obj_1")) == data
    backend.delete("obj_1")
    assert not backend.exists("obj_1")
    with pytest.raises(NotFound):
        list(backend.read("obj_1"))


@pytest.mark.parametrize("size", [10, 20 * 1024 * 1024 + 5])
def test_s3_backend(size: int) -> None:
    fake = _FakeS3()
    _exercise(S3BlobBackend("bucket", client=fake), size)
    assert fake.uploads == {}


def test_s3_abort_cleans_multipart() -> None:
    fake = _FakeS3()
    w = S3BlobBackend("bucket", client=fake).open_writer("obj_2")
    w.write(os.urandom(9 * 1024 * 1024))
    assert fake.uploads
    w.abort()
    assert fake.uploads == {}
    assert "objects/obj_2" not in fake.objects


def test_gcs_backend() -> None:
    _exercise(GcsBlobBackend("bucket", bucket=_FakeBucket()), 3_000_000)


def test_local_backend_rejects_traversal(tmp_path: Any) -> None:
    backend = LocalBlobBackend(tmp_path)
    with pytest.raises(ValueError):
        backend.open_writer("../escape")
    _exercise(backend, 1234)
