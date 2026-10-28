"""DrillRunner: Orchestrates end-to-end restore drills and verification."""

import os
import tempfile
import traceback
from typing import Dict, List, Optional, Tuple

from drillops.assertions import AssertionEvaluator
from drillops.certifier import CertificateGenerator
from drillops.engines.base import BaseRestoreEngine
from drillops.engines.postgres_engine import PostgresRestoreEngine
from drillops.engines.sqlite_engine import SQLiteRestoreEngine
from drillops.engines.mysql_engine import MySQLRestoreEngine
from drillops.models import AssertionResult, DrillSummary, VerificationConfig
from drillops.storage.archive import ArchiveProcessor
from drillops.core.rpo_auditor import RPOAuditor


class DrillRunner:
    """End-to-end executor for automated database restore drills."""

    @staticmethod
    def create_engine(config: VerificationConfig, work_dir: str) -> BaseRestoreEngine:
        """Instantiates the correct restore engine based on configuration."""
        db_type = config.database_type.lower()
        if db_type == "sqlite":
            target_path = os.path.join(work_dir, "ephemeral_drill.sqlite3")
            return SQLiteRestoreEngine(db_path=target_path)
        elif db_type in ("postgres", "postgresql"):
            return PostgresRestoreEngine(
                host=config.host or "localhost",
                port=config.port or 5432,
                user=config.user or os.environ.get("USER", "postgres"),
                password=config.password,
                admin_db=getattr(config, "admin_database", "postgres") or "postgres",
            )
        elif db_type in ("mysql", "mariadb"):
            admin_db = getattr(config, "admin_database", "mysql")
            if not admin_db or admin_db == "postgres":
                admin_db = "mysql"
            return MySQLRestoreEngine(
                host=config.host or "localhost",
                port=config.port or 3306,
                user=config.user,
                password=config.password,
                admin_db=admin_db,
            )
        else:
            raise ValueError(f"Unsupported database type: {config.database_type}. Supported: 'sqlite', 'postgres', 'mysql', 'mariadb'")


    def run_drill(
        self,
        config: VerificationConfig,
        output_dir: Optional[str] = None,
    ) -> Tuple[DrillSummary, List[AssertionResult], Dict[str, str]]:
        """
        Executes a complete restore drill:
        1. Checks backup file provenance and checksum
        2. Sets up isolated ephemeral database
        3. Restores backup
        4. Evaluates all integrity assertions
        5. Tears down database
        6. Generates compliance certificate
        """
        if not os.path.exists(config.backup_path):
            raise FileNotFoundError(f"Backup file not found at: {config.backup_path}")

        file_size, sha256 = ArchiveProcessor.inspect_file(config.backup_path)
        backup_name = os.path.basename(config.backup_path)
        enc_type = ArchiveProcessor.detect_encryption(config.backup_path)
        is_encrypted = bool(enc_type)

        rpo_report = RPOAuditor.audit_rpo(
            config.backup_path,
            max_rpo_hours=getattr(config, "max_rpo_hours", None),
        )

        summary = DrillSummary.create_new(
            database_type=config.database_type,
            backup_filename=backup_name,
            sha256=sha256,
            size=file_size,
            encrypted_at_rest=is_encrypted,
            encryption_type=enc_type,
            backup_timestamp=rpo_report.backup_timestamp.isoformat(),
            backup_age_hours=rpo_report.backup_age_hours,
            rpo_sla_hours=rpo_report.max_rpo_hours,
            rpo_status=rpo_report.status,
        )

        all_assertions: List[AssertionResult] = []
        artifacts: Dict[str, str] = {}

        with tempfile.TemporaryDirectory(prefix="drillops_work_") as work_dir:
            payload_path = ArchiveProcessor.prepare_archive(
                config.backup_path,
                work_dir,
                decrypt_passphrase=getattr(config, "decrypt_passphrase", None),
                decrypt_cipher=getattr(config, "decrypt_cipher", "aes-256-cbc") or "aes-256-cbc",
            )
            engine = self.create_engine(config, work_dir)

            try:
                # Step 1: Setup isolated sandbox
                engine.setup_ephemeral_db()

                # Step 2: Restore backup and record RTO
                restore_duration = engine.restore_dump(payload_path)
                summary.restore_duration_sec = round(restore_duration, 4)

                # Step 3: Run Assertion Evaluations
                evaluator = AssertionEvaluator(engine)

                # 3a. Automatic SOC2 CC6.1 Encryption assertion if encrypted
                if is_encrypted:
                    all_assertions.append(
                        AssertionResult(
                            rule_name="soc2_cc6_1_encryption_at_rest",
                            passed=True,
                            actual_value=f"verified ({enc_type})",
                            expected_value="encrypted",
                            execution_time_ms=0.1,
                            critical=True,
                        )
                    )

                # 3b. Table existence checks
                if config.expected_tables:
                    table_results = evaluator.verify_tables_exist(config.expected_tables)
                    all_assertions.extend(table_results)

                # 3c. Custom user query assertions
                for rule in config.assertion_rules:
                    rule_res = evaluator.evaluate_rule(rule)
                    all_assertions.extend([rule_res])

                # 3d. Automated PII & Sensitive Data Leak Scanning if requested
                if getattr(config, "scan_pii", False):
                    from drillops.assertions.pii_scanner import PIIScanner
                    pii_scanner = PIIScanner(engine)
                    pii_results = pii_scanner.evaluate_assertions()
                    all_assertions.extend(pii_results)

                # 3e. Automated RPO & Backup Freshness SLA assertion
                if getattr(config, "max_rpo_hours", None) is not None:
                    rpo_assertion = RPOAuditor.evaluate_assertion(rpo_report)
                    all_assertions.append(rpo_assertion)

                # 3f. Automated Cold-Storage Integrity & Checksum Manifest assertion
                if getattr(config, "verify_integrity", False) or getattr(config, "verify_manifest_path", None) is not None:
                    from drillops.storage.integrity import IntegrityAuditor
                    int_rep = IntegrityAuditor.audit(
                        config.backup_path,
                        manifest_path=getattr(config, "verify_manifest_path", None),
                    )
                    summary.integrity_status = int_rep.status
                    summary.checksum_manifest_verified = int_rep.manifest_matches
                    all_assertions.append(
                        AssertionResult(
                            rule_name="soc2_cc9_1_backup_integrity",
                            passed=not int_rep.corruption_detected,
                            actual_value=int_rep.status,
                            expected_value="VERIFIED",
                            execution_time_ms=1.0,
                            critical=True,
                            error=None if not int_rep.corruption_detected else int_rep.details,
                        )
                    )

                # 3g. Automated 3-2-1 Backup Redundancy & Cold-Storage Parity assertion
                if getattr(config, "replica_paths", []) or getattr(config, "require_321_redundancy", False):
                    from drillops.core.redundancy_auditor import RedundancyAuditor
                    red_rep = RedundancyAuditor.audit(
                        primary_location=config.backup_path,
                        replica_locations=getattr(config, "replica_paths", []),
                        max_replication_lag_hours=getattr(config, "max_replication_lag_hours", None),
                        require_321=getattr(config, "require_321_redundancy", False),
                    )
                    summary.redundancy_status = red_rep.status
                    summary.redundancy_copies_count = red_rep.total_copies_count
                    summary.redundancy_media_types_count = len(red_rep.distinct_media_types)
                    summary.replication_lag_hours = round(red_rep.observed_replication_lag_seconds / 3600.0, 3) if red_rep.observed_replication_lag_seconds else 0.0

                    passed_red = (red_rep.status == "COMPLIANT")
                    all_assertions.append(
                        AssertionResult(
                            rule_name="soc2_cc9_1_redundancy_321",
                            passed=passed_red,
                            actual_value=f"{red_rep.status} ({red_rep.total_copies_count} copies, {len(red_rep.distinct_media_types)} media, {red_rep.offsite_copies_count} offsite)",
                            expected_value="COMPLIANT",
                            execution_time_ms=1.0,
                            critical=getattr(config, "require_321_redundancy", False),
                            error=None if passed_red else red_rep.summary,
                        )
                    )

            except Exception as e:
                summary.overall_status = "FAILED"
                summary.failure_reasons.append(f"Fatal drill execution error: {str(e)}")
                traceback_str = traceback.format_exc()
                all_assertions.append(
                    AssertionResult(
                        rule_name="drill_execution_lifecycle",
                        passed=False,
                        actual_value="crashed",
                        expected_value="completed",
                        execution_time_ms=0.0,
                        critical=True,
                        error=f"{str(e)}\n{traceback_str}",
                    )
                )

            finally:
                # Step 4: Tear down sandbox
                if config.drop_on_completion:
                    try:
                        engine.teardown()
                    except Exception as td_err:
                        summary.failure_reasons.append(f"Teardown warning: {str(td_err)}")

        # Step 5: Compute summary metrics
        summary.total_assertions = len(all_assertions)
        summary.passed_assertions = sum(1 for a in all_assertions if a.passed)
        summary.failed_assertions = sum(1 for a in all_assertions if not a.passed)

        critical_failures = [a for a in all_assertions if not a.passed and a.critical]
        if critical_failures and summary.overall_status != "FAILED":
            summary.overall_status = "FAILED"
            for cf in critical_failures:
                summary.failure_reasons.append(f"Critical assertion failed: {cf.rule_name} ({cf.error})")
        elif not critical_failures and summary.overall_status != "FAILED":
            summary.overall_status = "PASSED"

        # Step 6: Generate artifacts if output_dir specified
        if output_dir:
            artifacts = CertificateGenerator.save_artifacts(output_dir, summary, all_assertions)

        return summary, all_assertions, artifacts
