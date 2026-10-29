"""Interactive guided demonstration and onboarding runner for DrillOps."""

import os
import sys
import tempfile
import time
from typing import Any, Dict, Optional

from drillops.compliance.audit_pack import AuditPackGenerator
from drillops.core.runner import DrillRunner
from drillops.generator.synthetic import SyntheticDataGenerator
from drillops.models import AssertionRule, VerificationConfig


class InteractiveDemoRunner:
    """Executes a guided self-contained terminal demo showcasing DrillOps capabilities."""

    @staticmethod
    def print_banner():
        from drillops import __version__
        banner = f"""
================================================================================
  🛡️  DRILLOPS INTERACTIVE DEMONSTRATION & QUICKSTART (v{__version__})
================================================================================
  "Schrödinger's Backup: The condition of any backup is unknown until you try
   to restore it. DrillOps verifies backups in isolated sandboxes continuously."
================================================================================
"""
        print(banner)

    def run_demo(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        self.print_banner()

        with tempfile.TemporaryDirectory(prefix="drillops_demo_") as tmpdir:
            work_dir = output_dir or tmpdir
            certs_dir = os.path.join(work_dir, "certificates")
            os.makedirs(certs_dir, exist_ok=True)

            gen = SyntheticDataGenerator(seed=42)

            # ------------------------------------------------------------------
            # Phase 1: Valid Backup Restore Drill
            # ------------------------------------------------------------------
            print("▶ STEP 1: Generating Production-Scale Test Backup...")
            valid_backup_path = os.path.join(tmpdir, "prod_backup_valid.sqlite")
            valid_meta = gen.generate_sqlite_file(valid_backup_path, num_records=250)
            print(f"  ✔ Created backup: {os.path.basename(valid_backup_path)} ({valid_meta['file_size']:,} bytes)")
            print(f"  ✔ Tables: {', '.join(valid_meta['tables'])}")
            print(f"  ✔ Records: {valid_meta['record_counts']['users']} users, {valid_meta['record_counts']['transactions']} transactions")
            print()

            print("▶ STEP 2: Executing Automated Restore Drill in Sandbox...")
            valid_config = VerificationConfig(
                database_type="sqlite",
                backup_path=valid_backup_path,
                expected_tables=["organizations", "users", "transactions", "audit_logs"],
                assertion_rules=[
                    AssertionRule(
                        name="min_user_count",
                        query="SELECT count(*) FROM users",
                        operator=">=",
                        expected_value=200,
                        critical=True,
                    ),
                    AssertionRule(
                        name="active_transaction_volume",
                        query="SELECT count(*) FROM transactions WHERE status = 'settled'",
                        operator=">",
                        expected_value=0,
                        critical=True,
                    ),
                ],
            )

            runner = DrillRunner()
            t0 = time.perf_counter()
            summary_valid, assertions_valid, artifacts_valid = runner.run_drill(valid_config, output_dir=certs_dir)
            t_elapsed = time.perf_counter() - t0

            print(f"  🟢 DRILL PASSED! [{summary_valid.certificate_id}]")
            print(f"     • Restore Duration (RTO): {summary_valid.restore_duration_sec:.4f}s")
            print(f"     • Assertions Evaluated:  {summary_valid.passed_assertions}/{summary_valid.total_assertions} Passed")
            print(f"     • Certificate (Markdown): {os.path.basename(artifacts_valid.get('markdown', ''))}")
            print(f"     • Certificate (JSON):     {os.path.basename(artifacts_valid.get('json', ''))}")
            print()

            # ------------------------------------------------------------------
            # Phase 2: Silent Corruption Detection
            # ------------------------------------------------------------------
            print("▶ STEP 3: Simulating Silent Backup Corruption (Dropped Table Defect)...")
            corrupt_backup_path = os.path.join(tmpdir, "prod_backup_corrupted.sqlite")
            gen.generate_sqlite_file(corrupt_backup_path, num_records=100, corrupt_mode="drop_table")
            print(f"  ⚠️  Injected defect: 'transactions' table omitted from backup stream.")
            print("     Running drill to test if DrillOps detects the deficit...")

            corrupt_config = VerificationConfig(
                database_type="sqlite",
                backup_path=corrupt_backup_path,
                expected_tables=["organizations", "users", "transactions"],
            )

            summary_corrupt, assertions_corrupt, artifacts_corrupt = runner.run_drill(corrupt_config, output_dir=certs_dir)

            print(f"  🔴 DEFECT CAUGHT! Drill correctly marked as FAILED [{summary_corrupt.certificate_id}]")
            print(f"     • Overall Status:  {summary_corrupt.overall_status}")
            print(f"     • Failed Checks:   {summary_corrupt.failed_assertions}")
            for r in summary_corrupt.failure_reasons:
                print(f"       ❌ {r}")
            print()

            # ------------------------------------------------------------------
            # Phase 3: SOC2 Compliance Dossier Generation
            # ------------------------------------------------------------------
            print("▶ STEP 4: Generating SOC2 / ISO 27001 Auditor Evidence Dossier...")
            audit_zip_path = os.path.join(work_dir, "drillops_demo_audit_pack.zip")
            generator = AuditPackGenerator(certs_dir)
            generator.export_pack_zip(audit_zip_path, company_name="Acme Corporation")
            print(f"  ✔ Generated Audit Dossier Archive: {audit_zip_path}")
            print("     Contains: AUDIT_DOSSIER.md, AUDIT_DOSSIER.html, manifest.json, and raw certificates.")
            print()

            # ------------------------------------------------------------------
            # Next Steps
            # ------------------------------------------------------------------
            print("================================================================")
            print("  🎉 DEMO COMPLETE! DrillOps is ready for your environment.")
            print("================================================================")
            print("  Quickstart Commands:")
            print("  1. Verify a backup:   drillops verify --backup db.sql.gz --type postgres --tables users,orders")
            print("  2. Run auto-watcher:  drillops watch --dir /var/backups --type postgres")
            print("  3. View dashboard:    drillops serve --port 8787")
            print("================================================================\n")

            return {
                "valid_certificate_id": summary_valid.certificate_id,
                "corrupt_certificate_id": summary_corrupt.certificate_id,
                "valid_status": summary_valid.overall_status,
                "corrupt_status": summary_corrupt.overall_status,
                "audit_pack_path": audit_zip_path,
            }
