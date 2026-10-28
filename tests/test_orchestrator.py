"""Integration tests for Multi-Target Declarative Watcher Orchestrator."""

import json
import os
import tempfile
import pytest

from drillops.daemon.orchestrator import MultiTargetOrchestrator, OrchestratorConfig, TargetDefinition
from drillops.generator.synthetic import SyntheticDataGenerator
from drillops.licensing import LicenseGenerator, LicenseTier, LicenseValidator


def test_orchestrator_config_from_dict():
    raw_config = {
        "output_dir": "/tmp/out",
        "targets": [
            {
                "name": "core_sqlite",
                "database_type": "sqlite",
                "storage_type": "local",
                "storage_path": "/tmp/backups1",
                "expected_tables": ["users", "orders"],
            },
            {
                "name": "replica_sqlite",
                "database_type": "sqlite",
                "storage_type": "local",
                "storage_path": "/tmp/backups2",
            },
        ],
    }
    cfg = OrchestratorConfig.from_dict(raw_config)
    assert len(cfg.targets) == 2
    assert cfg.targets[0].name == "core_sqlite"
    assert cfg.targets[0].expected_tables == ["users", "orders"]
    assert cfg.targets[1].name == "replica_sqlite"


def test_orchestrator_community_tier_limits_to_one_target():
    with tempfile.TemporaryDirectory() as tmpdir:
        t1_dir = os.path.join(tmpdir, "t1")
        t2_dir = os.path.join(tmpdir, "t2")
        out_dir = os.path.join(tmpdir, "certs")

        gen = SyntheticDataGenerator(seed=1)
        gen.generate_sqlite_file(os.path.join(t1_dir, "db1.sqlite"), num_records=20)
        gen.generate_sqlite_file(os.path.join(t2_dir, "db2.sqlite"), num_records=20)

        cfg = OrchestratorConfig(
            targets=[
                TargetDefinition("t1", "sqlite", "local", t1_dir, ["users"]),
                TargetDefinition("t2", "sqlite", "local", t2_dir, ["users"]),
            ],
            output_dir=out_dir,
        )

        # Community validator (no license)
        validator = LicenseValidator()
        orchestrator = MultiTargetOrchestrator(cfg, license_validator=validator)
        results = orchestrator.run_all_once()

        assert "t1" in results
        assert results["t1"] is not None
        assert results["t1"].overall_status == "PASSED"
        # t2 should not be run under Community tier
        assert "t2" not in results


def test_orchestrator_pro_tier_executes_multiple_targets():
    secret = "orch-test-secret"
    lic_gen = LicenseGenerator(secret=secret)
    pro_token = lic_gen.mint_license("Pro Customer", "pro@corp.com", LicenseTier.PRO, max_targets=10)

    with tempfile.TemporaryDirectory() as tmpdir:
        t1_dir = os.path.join(tmpdir, "t1")
        t2_dir = os.path.join(tmpdir, "t2")
        out_dir = os.path.join(tmpdir, "certs")

        gen = SyntheticDataGenerator(seed=1)
        gen.generate_sqlite_file(os.path.join(t1_dir, "db1.sqlite"), num_records=20)
        gen.generate_sqlite_file(os.path.join(t2_dir, "db2.sqlite"), num_records=20)

        cfg = OrchestratorConfig(
            targets=[
                TargetDefinition("t1", "sqlite", "local", t1_dir, ["users"]),
                TargetDefinition("t2", "sqlite", "local", t2_dir, ["users"]),
            ],
            output_dir=out_dir,
        )

        class ProValidator(LicenseValidator):
            def __init__(self):
                super().__init__(secret=secret)
            def validate_key(self, token=None):
                return super().validate_key(pro_token)

        orchestrator = MultiTargetOrchestrator(cfg, license_validator=ProValidator())
        results = orchestrator.run_all_once()

        assert "t1" in results
        assert "t2" in results
        assert results["t1"] is not None and results["t1"].overall_status == "PASSED"
        assert results["t2"] is not None and results["t2"].overall_status == "PASSED"
