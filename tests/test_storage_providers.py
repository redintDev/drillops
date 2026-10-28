"""Tests for storage providers (Local and Mock S3)."""

import os
import time
import pytest
from drillops.storage.providers import LocalStorageProvider, MockS3StorageProvider


def test_local_storage_provider(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    # Create dummy files with different timestamps
    file1 = backup_dir / "backup_2026-10-01.sql"
    file1.write_text("DUMP 1")
    os.utime(file1, (1000, 1000))

    file2 = backup_dir / "backup_2026-10-08.sql"
    file2.write_text("DUMP 2")
    os.utime(file2, (2000, 2000))

    provider = LocalStorageProvider(str(backup_dir), glob_pattern="*.sql")
    backups = provider.list_backups()

    assert len(backups) == 2
    # Newest should be first
    assert backups[0].filename == "backup_2026-10-08.sql"
    assert backups[1].filename == "backup_2026-10-01.sql"

    dest_dir = tmp_path / "downloads"
    dest_dir.mkdir()
    fetched = provider.fetch_latest(str(dest_dir))

    assert os.path.exists(fetched)
    assert os.path.basename(fetched) == "backup_2026-10-08.sql"
    assert open(fetched).read() == "DUMP 2"


def test_mock_s3_storage_provider(tmp_path):
    provider = MockS3StorageProvider(bucket_name="my-production-backups")
    provider.put_mock_object("daily/2026-10-01.sql.gz", b"MOCK DATA 1", timestamp=100.0)
    provider.put_mock_object("daily/2026-10-08.sql.gz", b"MOCK DATA 2", timestamp=200.0)

    backups = provider.list_backups()
    assert len(backups) == 2
    assert backups[0].filename == "2026-10-08.sql.gz"

    dest_dir = tmp_path / "s3_downloads"
    dest_dir.mkdir()
    fetched = provider.fetch_latest(str(dest_dir))

    assert os.path.exists(fetched)
    assert os.path.basename(fetched) == "2026-10-08.sql.gz"
    assert open(fetched, "rb").read() == b"MOCK DATA 2"


def test_parse_s3_uri():
    from drillops.storage.providers import parse_s3_uri

    bucket, key = parse_s3_uri("s3://prod-backups/postgres/2026-10-10.dump")
    assert bucket == "prod-backups"
    assert key == "postgres/2026-10-10.dump"

    bucket2, key2 = parse_s3_uri("s3://backup-vault")
    assert bucket2 == "backup-vault"
    assert key2 == ""

    bucket3, key3 = parse_s3_uri("s3://vault/folder/")
    assert bucket3 == "vault"
    assert key3 == "folder/"

    with pytest.raises(ValueError):
        parse_s3_uri("https://example.com/file.dump")


def test_get_storage_provider_factory():
    from drillops.storage.providers import (
        LocalStorageProvider,
        S3CompatibleStorageProvider,
        get_storage_provider,
    )

    prov_local = get_storage_provider("/var/backups")
    assert isinstance(prov_local, LocalStorageProvider)

    prov_s3 = get_storage_provider("s3://company-vault/daily/")
    assert isinstance(prov_s3, S3CompatibleStorageProvider)
    assert prov_s3.bucket_name == "company-vault"
    assert prov_s3.prefix == "daily/"


def test_s3_compatible_storage_provider_with_mock_client(tmp_path):
    from datetime import datetime, timezone
    from unittest.mock import MagicMock
    from drillops.storage.providers import S3CompatibleStorageProvider

    # Mock boto3 client
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    # Mock paginator return pages
    page_data = {
        "Contents": [
            {
                "Key": "backups/old.sql.gz",
                "Size": 1024,
                "LastModified": datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc),
            },
            {
                "Key": "backups/latest.sql.gz",
                "Size": 2048,
                "LastModified": datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc),
            },
            {
                "Key": "backups/readme.txt",
                "Size": 50,
                "LastModified": datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc),
            },
            {
                "Key": "backups/",  # Directory marker
                "Size": 0,
                "LastModified": datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc),
            },
        ]
    }
    mock_paginator.paginate.return_value = [page_data]

    # Mock download_file
    def fake_download(bucket, key, dest):
        with open(dest, "wb") as f:
            f.write(b"MOCK DOWNLOADED BYTES")

    mock_client.download_file.side_effect = fake_download

    provider = S3CompatibleStorageProvider(
        bucket_name="my-cloud-bucket",
        prefix="backups/",
        glob_pattern="*.sql.gz",
        s3_client=mock_client,
    )

    backups = provider.list_backups()
    assert len(backups) == 2
    # Newest sql.gz should be first
    assert backups[0].filename == "latest.sql.gz"
    assert backups[0].size_bytes == 2048
    assert backups[0].source_uri == "s3://my-cloud-bucket/backups/latest.sql.gz"
    assert backups[1].filename == "old.sql.gz"

    dest_dir = tmp_path / "cloud_dest"
    dest_dir.mkdir()
    fetched = provider.fetch_latest(str(dest_dir))

    assert os.path.exists(fetched)
    assert os.path.basename(fetched) == "latest.sql.gz"
    assert open(fetched, "rb").read() == b"MOCK DOWNLOADED BYTES"
    mock_client.download_file.assert_called_with(
        "my-cloud-bucket", "backups/latest.sql.gz", fetched
    )


def test_s3_compatible_storage_provider_empty_bucket():
    from unittest.mock import MagicMock
    from drillops.storage.providers import S3CompatibleStorageProvider

    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{"Contents": []}]

    provider = S3CompatibleStorageProvider(
        bucket_name="empty-bucket",
        s3_client=mock_client,
    )

    assert provider.list_backups() == []
    with pytest.raises(FileNotFoundError):
        provider.fetch_latest("/tmp")

