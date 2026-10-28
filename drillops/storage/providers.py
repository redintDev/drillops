"""Storage providers for discovering and downloading database backups."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import glob
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BackupMetadata:
    """Metadata describing a discovered database backup archive."""
    filename: str
    source_uri: str
    size_bytes: int
    modified_timestamp: float
    storage_type: str  # 'local', 's3', 'mock'


class BaseStorageProvider(ABC):
    """Abstract interface for backup storage backends."""

    @abstractmethod
    def list_backups(self) -> List[BackupMetadata]:
        """Enumerate available backup archives."""
        pass

    @abstractmethod
    def fetch_latest(self, destination_dir: str) -> str:
        """Download or copy the latest backup archive to destination_dir."""
        pass


class LocalStorageProvider(BaseStorageProvider):
    """Discovers and retrieves backups from local or mounted storage volumes."""

    def __init__(self, directory_path: str, glob_pattern: str = "*"):
        self.directory_path = os.path.abspath(directory_path)
        self.glob_pattern = glob_pattern

    def list_backups(self) -> List[BackupMetadata]:
        if not os.path.isdir(self.directory_path):
            return []

        search_pattern = os.path.join(self.directory_path, self.glob_pattern)
        matched_files = [f for f in glob.glob(search_pattern) if os.path.isfile(f)]

        results = []
        for path in matched_files:
            stat = os.stat(path)
            results.append(
                BackupMetadata(
                    filename=os.path.basename(path),
                    source_uri=f"file://{path}",
                    size_bytes=stat.st_size,
                    modified_timestamp=stat.st_mtime,
                    storage_type="local",
                )
            )

        # Sort by modification time descending (latest first)
        results.sort(key=lambda b: b.modified_timestamp, reverse=True)
        return results

    def fetch_latest(self, destination_dir: str) -> str:
        backups = self.list_backups()
        if not backups:
            raise FileNotFoundError(f"No backup files found matching '{self.glob_pattern}' in {self.directory_path}")

        latest = backups[0]
        source_path = latest.source_uri.replace("file://", "")
        dest_path = os.path.join(destination_dir, latest.filename)

        # If already in destination, return directly; otherwise copy
        if os.path.abspath(source_path) == os.path.abspath(dest_path):
            return dest_path

        shutil.copy2(source_path, dest_path)
        return dest_path


class MockS3StorageProvider(BaseStorageProvider):
    """Simulates S3 / R2 / GCS bucket operations for offline testing and air-gapped CI."""

    def __init__(self, bucket_name: str, endpoint_url: Optional[str] = None):
        self.bucket_name = bucket_name
        self.endpoint_url = endpoint_url or "https://s3.amazonaws.com"
        self._objects: Dict[str, bytes] = {}
        self._timestamps: Dict[str, float] = {}

    def put_mock_object(self, key: str, data: bytes, timestamp: float = 1700000000.0) -> None:
        """Seed a mock backup file in the bucket."""
        self._objects[key] = data
        self._timestamps[key] = timestamp

    def list_backups(self) -> List[BackupMetadata]:
        results = []
        for key, data in self._objects.items():
            results.append(
                BackupMetadata(
                    filename=os.path.basename(key),
                    source_uri=f"s3://{self.bucket_name}/{key}",
                    size_bytes=len(data),
                    modified_timestamp=self._timestamps.get(key, 0.0),
                    storage_type="mock_s3",
                )
            )
        results.sort(key=lambda b: b.modified_timestamp, reverse=True)
        return results

    def fetch_latest(self, destination_dir: str) -> str:
        backups = self.list_backups()
        if not backups:
            raise FileNotFoundError(f"Bucket 's3://{self.bucket_name}' contains no backup objects")

        latest = backups[0]
        prefix = f"s3://{self.bucket_name}/"
        object_key = latest.source_uri[len(prefix):] if latest.source_uri.startswith(prefix) else latest.filename
        dest_path = os.path.join(destination_dir, latest.filename)
        data = self._objects[object_key]
        with open(dest_path, "wb") as f:
            f.write(data)

        return dest_path


def parse_s3_uri(uri: str) -> Tuple[str, str]:
    """Parses an s3://bucket/key URI into (bucket_name, key_or_prefix)."""
    if not uri.startswith("s3://"):
        raise ValueError(f"Invalid S3 URI: '{uri}'. Must start with 's3://'")
    without_scheme = uri[5:]
    if "/" in without_scheme:
        bucket, key = without_scheme.split("/", 1)
    else:
        bucket, key = without_scheme, ""
    return bucket, key


class S3CompatibleStorageProvider(BaseStorageProvider):
    """
    Discovers and downloads database backups from AWS S3, Cloudflare R2,
    MinIO, DigitalOcean Spaces, or any S3-compatible object store.
    """

    def __init__(
        self,
        bucket_name: str,
        prefix: str = "",
        endpoint_url: Optional[str] = None,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        glob_pattern: Optional[str] = None,
        s3_client: Optional[Any] = None,
    ):
        self.bucket_name = bucket_name
        self.prefix = prefix.lstrip("/")
        self.endpoint_url = endpoint_url or os.environ.get("AWS_ENDPOINT_URL") or os.environ.get("S3_ENDPOINT_URL")
        self.region_name = region_name or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self.aws_access_key_id = aws_access_key_id or os.environ.get("AWS_ACCESS_KEY_ID")
        self.aws_secret_access_key = aws_secret_access_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.glob_pattern = glob_pattern
        self._s3_client = s3_client

    @property
    def client(self) -> Any:
        if self._s3_client is not None:
            return self._s3_client
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for S3CompatibleStorageProvider. "
                "Install it with: pip install boto3"
            )

        client_kwargs: Dict[str, Any] = {
            "service_name": "s3",
            "region_name": self.region_name,
        }
        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url
        if self.aws_access_key_id and self.aws_secret_access_key:
            client_kwargs["aws_access_key_id"] = self.aws_access_key_id
            client_kwargs["aws_secret_access_key"] = self.aws_secret_access_key

        self._s3_client = boto3.client(**client_kwargs)
        return self._s3_client

    @classmethod
    def from_uri(
        cls,
        uri: str,
        endpoint_url: Optional[str] = None,
        region_name: Optional[str] = None,
        glob_pattern: Optional[str] = None,
        s3_client: Optional[Any] = None,
        **kwargs,
    ) -> "S3CompatibleStorageProvider":
        bucket, prefix = parse_s3_uri(uri)
        return cls(
            bucket_name=bucket,
            prefix=prefix,
            endpoint_url=endpoint_url,
            region_name=region_name,
            glob_pattern=glob_pattern,
            s3_client=s3_client,
            **kwargs,
        )

    def list_backups(self) -> List[BackupMetadata]:
        import fnmatch

        client = self.client
        results = []
        paginator = client.get_paginator("list_objects_v2")
        paginate_kwargs = {"Bucket": self.bucket_name}
        if self.prefix:
            paginate_kwargs["Prefix"] = self.prefix

        try:
            pages = paginator.paginate(**paginate_kwargs)
            for page in pages:
                contents = page.get("Contents", [])
                for obj in contents:
                    key = obj.get("Key", "")
                    if key.endswith("/") or obj.get("Size", 0) == 0:
                        continue

                    filename = os.path.basename(key)
                    if self.glob_pattern and not fnmatch.fnmatch(filename, self.glob_pattern):
                        continue

                    last_modified = obj.get("LastModified")
                    mtime = last_modified.timestamp() if hasattr(last_modified, "timestamp") else float(last_modified or 0)

                    results.append(
                        BackupMetadata(
                            filename=filename,
                            source_uri=f"s3://{self.bucket_name}/{key}",
                            size_bytes=obj.get("Size", 0),
                            modified_timestamp=mtime,
                            storage_type="s3",
                        )
                    )
        except Exception as e:
            if "NoSuchBucket" in str(e):
                raise FileNotFoundError(f"S3 Bucket '{self.bucket_name}' not found.") from e
            raise

        results.sort(key=lambda b: b.modified_timestamp, reverse=True)
        return results

    def fetch_latest(self, destination_dir: str) -> str:
        backups = self.list_backups()
        if not backups:
            raise FileNotFoundError(
                f"Bucket 's3://{self.bucket_name}' (prefix='{self.prefix}') contains no valid backup objects."
            )
        latest = backups[0]
        prefix = f"s3://{self.bucket_name}/"
        object_key = latest.source_uri[len(prefix):] if latest.source_uri.startswith(prefix) else latest.filename
        return self.download_object(object_key, destination_dir)

    def download_object(self, object_key: str, destination_dir: str) -> str:
        """Downloads a specific S3 object key into destination_dir."""
        os.makedirs(destination_dir, exist_ok=True)
        filename = os.path.basename(object_key)
        dest_path = os.path.join(destination_dir, filename)
        client = self.client
        client.download_file(self.bucket_name, object_key, dest_path)
        return dest_path


def get_storage_provider(path_or_uri: str, **kwargs) -> BaseStorageProvider:
    """Returns appropriate storage provider for local path or cloud s3:// URI."""
    if path_or_uri.startswith("s3://"):
        return S3CompatibleStorageProvider.from_uri(path_or_uri, **kwargs)
    return LocalStorageProvider(path_or_uri, **kwargs)

