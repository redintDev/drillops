"""Tests for DrillWatcher daemon and automated scheduling."""

import json
import os
import pytest

from drillops.daemon.watcher import DrillWatcher
from drillops.models import VerificationConfig
from drillops.storage.providers import MockS3StorageProvider


def test_drill_watcher_lifecycle(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    state_file = tmp_path / "state.json"

    # Seed mock bucket
    provider = MockS3StorageProvider(bucket_name="auto-backups")
    sql_content = b"CREATE TABLE users (id INT PRIMARY KEY); INSERT INTO users VALUES (1);"
    provider.put_mock_object("daily.sql", sql_content, timestamp=100.0)

    config = VerificationConfig(
        database_type="sqlite",
        backup_path="",  # will be dynamically set by watcher
        expected_tables=["users"],
    )

    watcher = DrillWatcher(
        provider=provider,
        config=config,
        output_dir=str(cert_dir),
        state_file=str(state_file),
    )

    # First run: should discover, execute drill, and record state
    summary = watcher.check_and_run_once()
    assert summary is not None
    assert summary.overall_status == "PASSED"
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)
    assert summary.backup_sha256 in state["processed_hashes"]

    # Second run without new backup: should skip execution
    summary_second = watcher.check_and_run_once()
    assert summary_second is None

    # Seed updated backup with new timestamp and content
    new_sql = b"CREATE TABLE users (id INT PRIMARY KEY); INSERT INTO users VALUES (1), (2);"
    provider.put_mock_object("daily.sql", new_sql, timestamp=200.0)

    summary_third = watcher.check_and_run_once()
    assert summary_third is not None
    assert summary_third.overall_status == "PASSED"


def test_drill_watcher_with_s3_compatible_provider(tmp_path):
    from datetime import datetime, timezone
    from unittest.mock import MagicMock
    from drillops.storage.providers import S3CompatibleStorageProvider

    cert_dir = tmp_path / "certs_s3"
    cert_dir.mkdir()
    state_file = tmp_path / "state_s3.json"

    sql_content = b"CREATE TABLE accounts (id INT PRIMARY KEY, balance INT); INSERT INTO accounts VALUES (1, 500);"

    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {
            "Contents": [
                {
                    "Key": "vault/prod.sql",
                    "Size": len(sql_content),
                    "LastModified": datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc),
                }
            ]
        }
    ]

    def fake_download(bucket, key, dest):
        with open(dest, "wb") as f:
            f.write(sql_content)

    mock_client.download_file.side_effect = fake_download

    provider = S3CompatibleStorageProvider(
        bucket_name="enterprise-vault",
        prefix="vault/",
        s3_client=mock_client,
    )

    config = VerificationConfig(
        database_type="sqlite",
        backup_path="",
        expected_tables=["accounts"],
    )

    watcher = DrillWatcher(
        provider=provider,
        config=config,
        output_dir=str(cert_dir),
        state_file=str(state_file),
    )

    summary = watcher.check_and_run_once()
    assert summary is not None
    assert summary.overall_status == "PASSED"
    assert summary.backup_filename == "prod.sql"
    assert os.path.exists(state_file)

