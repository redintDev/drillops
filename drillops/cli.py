"""Command-line interface for DrillOps."""

import argparse
import json
import os
import shutil
import sys
import tempfile
from typing import List

from drillops import __version__
from drillops.core.runner import DrillRunner
from drillops.models import AssertionRule, VerificationConfig
from drillops.notifications import NotificationConfig, NotificationDispatcher


def parse_args(args: List[str] = None):
    parser = argparse.ArgumentParser(
        prog="drillops",
        description="DrillOps: Automated Database Restore Drill Runner & SOC2 Compliance Certifier",
    )
    parser.add_argument(
        "--version", "-v", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'verify' subcommand
    verify_parser = subparsers.add_parser("verify", help="Run a database restore drill against a backup")
    verify_parser.add_argument("--backup", "-b", help="Path or s3:// URI to database backup file (.dump, .sql, .sql.gz, .sqlite)")
    verify_parser.add_argument("--type", "-t", choices=["sqlite", "postgres", "mysql", "mariadb"], default="sqlite", help="Target database engine")
    verify_parser.add_argument("--tables", help="Comma-separated list of expected critical tables")
    verify_parser.add_argument("--out", "-o", default="./certificates", help="Output directory for certificates")
    verify_parser.add_argument("--config", "-c", help="Path to JSON configuration file overriding CLI flags")
    verify_parser.add_argument("--host", default="localhost", help="Database host (for postgres)")
    verify_parser.add_argument("--port", type=int, default=5432, help="Database port (for postgres)")
    verify_parser.add_argument("--user", default="postgres", help="Database username (for postgres)")
    verify_parser.add_argument("--s3-endpoint-url", help="Custom S3/R2 endpoint URL (for Cloudflare R2, MinIO)")
    verify_parser.add_argument("--s3-region", help="Cloud storage region (for S3)")
    verify_parser.add_argument("--notify-webhook", help="Webhook URL to dispatch results")
    verify_parser.add_argument("--notify-slack", help="Slack webhook URL to dispatch results")
    verify_parser.add_argument("--notify-discord", help="Discord webhook URL to dispatch results")
    verify_parser.add_argument("--notify-pagerduty", help="PagerDuty routing key to dispatch alerts")
    verify_parser.add_argument("--notify-vanta", help="Vanta custom test webhook URL to upload compliance evidence")
    verify_parser.add_argument("--notify-drata", help="Drata custom test webhook URL to upload compliance evidence")
    verify_parser.add_argument("--decrypt-passphrase", help="Passphrase to decrypt encrypted backup archives (or reads DRILLOPS_DECRYPT_PASSPHRASE)")
    verify_parser.add_argument("--decrypt-cipher", default="aes-256-cbc", help="Cipher algorithm for OpenSSL decryption (default: aes-256-cbc)")
    verify_parser.add_argument("--scan-pii", action="store_true", help="Scan restored database for unmasked customer PII/secrets (SOC2 CC6.1)")
    verify_parser.add_argument("--max-rpo-hours", type=float, help="Maximum allowed backup age in hours (Recovery Point Objective SLA threshold)")
    verify_parser.add_argument("--replica", action="append", default=[], help="Path or s3:// URI to replica backup copy for 3-2-1 redundancy validation (can specify multiple)")
    verify_parser.add_argument("--max-replication-lag-hours", type=float, help="Maximum allowed replication synchronization lag in hours")
    verify_parser.add_argument("--require-321", action="store_true", help="Enforce strict 3-2-1 backup redundancy rule (3 copies, 2 media types, 1 offsite)")
    verify_parser.add_argument("--verify-manifest", help="Path to cryptographic checksum manifest (.sha256, SHA256SUMS)")
    verify_parser.add_argument("--verify-integrity", action="store_true", help="Verify cold-storage bit-rot and archive stream integrity")

    # 'serve' subcommand
    serve_parser = subparsers.add_parser("serve", help="Launch the embedded compliance dashboard and API")
    serve_parser.add_argument("--port", "-p", type=int, default=8787, help="Server port")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Server host")
    serve_parser.add_argument("--out", "-o", default="./certificates", help="Certificates directory")

    # 'watch' subcommand
    watch_parser = subparsers.add_parser("watch", help="Run the automated backup watcher daemon")
    watch_parser.add_argument("--dir", "-d", required=True, help="Directory path or s3:// bucket URI to monitor for new backups")
    watch_parser.add_argument("--type", "-t", choices=["sqlite", "postgres", "mysql", "mariadb"], default="sqlite", help="Target database engine")
    watch_parser.add_argument("--out", "-o", default="./certificates", help="Certificates directory")
    watch_parser.add_argument("--endpoint-url", help="Custom S3/R2 endpoint URL (for Cloudflare R2, MinIO)")
    watch_parser.add_argument("--region", help="Cloud storage region")
    watch_parser.add_argument("--max-rpo-hours", type=float, help="Maximum allowed backup age in hours (Recovery Point Objective SLA threshold)")
    watch_parser.add_argument("--once", action="store_true", help="Run single poll and exit")

    # 'orchestrate' subcommand (Multi-target)
    orch_parser = subparsers.add_parser("orchestrate", help="Run multi-target database watcher orchestrator")
    orch_parser.add_argument("--config", "-c", required=True, help="Path to multi-target JSON config file")
    orch_parser.add_argument("--once", action="store_true", help="Run single verification pass across targets and exit")

    # 'demo' subcommand
    demo_parser = subparsers.add_parser("demo", help="Run guided interactive demonstration and onboarding walkthrough")
    demo_parser.add_argument("--out", "-o", default="./demo_artifacts", help="Output directory for demo certificates")

    # 'license' subcommand
    license_parser = subparsers.add_parser("license", help="Verify or inspect DrillOps commercial licenses")
    license_parser.add_argument("action", choices=["verify", "info"], help="License action ('verify' or 'info')")
    license_parser.add_argument("--key", "-k", help="License key token (or reads DRILLOPS_LICENSE_KEY)")

    # 'audit-pack' subcommand
    audit_parser = subparsers.add_parser("audit-pack", help="Generate an auditor-ready SOC2/ISO 27001 evidence package")
    audit_parser.add_argument("--cert-dir", default="./certificates", help="Directory containing drill certificates")
    audit_parser.add_argument("--out", "-o", default="audit_dossier.zip", help="Output ZIP file path")
    audit_parser.add_argument("--days", type=int, default=None, help="Filter to last N days (default: all)")
    audit_parser.add_argument("--company", default="Organization", help="Company/Organization name for the dossier")

    # 'generate-backup' subcommand
    gen_parser = subparsers.add_parser("generate-backup", help="Generate synthetic test backups with optional corruption")
    gen_parser.add_argument("--engine", choices=["sqlite", "postgres", "mysql"], default="sqlite", help="Target engine")
    gen_parser.add_argument("--records", type=int, default=500, help="Number of synthetic user records")
    gen_parser.add_argument("--out", "-o", required=True, help="Output backup path")
    gen_parser.add_argument("--compress", action="store_true", help="Compress with gzip (Postgres/MySQL only)")
    gen_parser.add_argument("--corrupt-mode", choices=["none", "truncate", "header_garbage", "drop_table", "syntax_error"], default="none", help="Simulate backup defect")


    # 'notify-test' subcommand
    test_notify_parser = subparsers.add_parser("notify-test", help="Test webhook and alerting configuration")
    test_notify_parser.add_argument("--webhook", required=True, help="Destination webhook URL")
    test_notify_parser.add_argument("--type", choices=["generic", "slack", "discord", "pagerduty", "vanta", "drata"], default="generic", help="Notification channel")
    test_notify_parser.add_argument("--secret", help="HMAC secret for generic webhooks")

    # 'checklist' subcommand
    chk_parser = subparsers.add_parser("checklist", help="Generate SOC2 CC9.1 / ISO 27001 disaster recovery audit preparation checklist")
    chk_parser.add_argument("--cert-dir", default="./certificates", help="Directory containing drill certificates to evaluate")
    chk_parser.add_argument("--out", "-o", help="Optional output path to save Markdown checklist (e.g. ./SOC2_CHECKLIST.md)")
    chk_parser.add_argument("--company", default="Organization", help="Company name for checklist evaluation")
    chk_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format")

    # 'badge' subcommand
    badge_parser = subparsers.add_parser("badge", help="Generate SVG or Shields.io compliance badge for disaster recovery verification")
    badge_parser.add_argument("--cert-dir", default="./certificates", help="Directory containing drill certificates to evaluate")
    badge_parser.add_argument("--out", "-o", help="Optional output path to save SVG badge file (e.g. ./drillops_badge.svg)")
    badge_parser.add_argument("--shields-json", action="store_true", help="Output Shields.io JSON endpoint payload")
    badge_parser.add_argument("--markdown", action="store_true", help="Print Markdown embed snippet for README.md")

    # 'doctor' subcommand
    doc_parser = subparsers.add_parser("doctor", help="Run system diagnostics and pre-flight readiness inspection")
    doc_parser.add_argument("--cert-dir", default="./certificates", help="Directory for certificate storage")
    doc_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON status")

    # 'systemd' subcommand
    sysd_parser = subparsers.add_parser("systemd", help="Generate Linux systemd service unit file for DrillOps daemons")
    sysd_parser.add_argument("--user", help="Run systemd service as specified user (default: current user)")
    sysd_parser.add_argument("--dir", help="Working directory for daemon (default: current directory)")
    sysd_parser.add_argument("--cmd", default="watch --dir /var/backups --type postgres", help="Command arguments to execute")
    sysd_parser.add_argument("--out", "-o", help="Optional output path to save service file (e.g. ./drillops.service)")

    # 'metrics' subcommand
    metrics_parser = subparsers.add_parser("metrics", help="Export Prometheus metrics in standard exposition format")
    metrics_parser.add_argument("--cert-dir", default="./certificates", help="Directory containing drill certificates")
    metrics_parser.add_argument("--out", "-o", help="Optional output path to save metrics file (e.g. /var/lib/node_exporter/drillops.prom)")
    metrics_parser.add_argument("--json", action="store_true", help="Output metrics as structured JSON instead of Prometheus text")

    # 'scan-pii' subcommand
    pii_parser = subparsers.add_parser("scan-pii", help="Scan a database backup sandbox for unmasked PII, credentials, and secrets")
    pii_parser.add_argument("--backup", "-b", required=True, help="Path to database backup file")
    pii_parser.add_argument("--type", "-t", choices=["sqlite", "postgres", "mysql", "mariadb"], default="sqlite", help="Target database engine")
    pii_parser.add_argument("--tables", help="Comma-separated list of specific tables to scan (default: all tables)")
    pii_parser.add_argument("--max-rows", type=int, default=100, help="Maximum sample rows to inspect per table")
    pii_parser.add_argument("--decrypt-passphrase", help="Passphrase to decrypt backup if encrypted")
    pii_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON findings")

    # 'check-rpo' subcommand
    rpo_parser = subparsers.add_parser("check-rpo", help="Audit backup freshness and evaluate Recovery Point Objective (RPO) SLA")
    rpo_parser.add_argument("--backup", "-b", required=True, help="Path to database backup file")
    rpo_parser.add_argument("--max-rpo-hours", type=float, help="Maximum allowed backup age in hours (RPO SLA threshold)")
    rpo_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON status")

    # 'check-redundancy' subcommand
    red_parser = subparsers.add_parser("check-redundancy", help="Audit backup redundancy across locations and verify 3-2-1 compliance")
    red_parser.add_argument("--primary", "-p", required=True, help="Path or s3:// URI to primary backup")
    red_parser.add_argument("--replica", "-r", action="append", required=True, help="Path or s3:// URI to replica backup (can specify multiple)")
    red_parser.add_argument("--max-lag-hours", type=float, help="Maximum allowed replication lag in hours")
    red_parser.add_argument("--require-321", action="store_true", help="Enforce strict 3-2-1 rule (3 copies, 2 media types, 1 offsite)")
    red_parser.add_argument("--s3-endpoint-url", help="Custom S3/R2 endpoint URL")
    red_parser.add_argument("--s3-region", help="Cloud storage region")
    red_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")

    # 'check-integrity' subcommand
    int_parser = subparsers.add_parser("check-integrity", help="Audit cold-storage backup bit-rot, corruption, and checksum manifests")
    int_parser.add_argument("--backup", "-b", required=True, help="Path to database backup archive")
    int_parser.add_argument("--manifest", "-m", help="Optional path to checksum manifest (.sha256, SHA256SUMS)")
    int_parser.add_argument("--generate-manifest", action="store_true", help="Generate a .sha256 manifest file alongside the backup")
    int_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")

    # 'report' subcommand
    report_parser = subparsers.add_parser("report", help="Generate standalone CISO executive disaster recovery audit report (HTML)")
    report_parser.add_argument("--cert", "-c", required=True, help="Path to drill certificate JSON file")
    report_parser.add_argument("--out", "-o", help="Output HTML file path (default: alongside certificate)")
    report_parser.add_argument("--company", default="Organization", help="Company name for executive attestation")
    report_parser.add_argument("--json", action="store_true", help="Output metadata as JSON")

    # 'check-pitr' subcommand
    pitr_parser = subparsers.add_parser("check-pitr", help="Audit PostgreSQL Write-Ahead Log (WAL) archive continuity for PITR")
    pitr_parser.add_argument("--wal-dir", "-w", required=True, help="Path to PostgreSQL WAL archive directory")
    pitr_parser.add_argument("--wal-size-mb", type=int, default=16, help="Expected WAL segment size in MB (default: 16)")
    pitr_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")

    # 'check-binlog' subcommand
    binlog_parser = subparsers.add_parser("check-binlog", help="Audit MySQL/MariaDB Binary Log (binlog) continuity for PITR")
    binlog_parser.add_argument("--binlog-dir", "-b", required=True, help="Path to MySQL/MariaDB binary log directory")
    binlog_parser.add_argument("--prefix", "-p", help="Optional binlog filename prefix (e.g. mysql-bin or binlog)")
    binlog_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")

    return parser.parse_args(args)



def main(args: List[str] = None) -> int:
    parsed = parse_args(args)

    if parsed.command == "verify":
        passphrase = getattr(parsed, "decrypt_passphrase", None) or os.environ.get("DRILLOPS_DECRYPT_PASSPHRASE")
        cipher = getattr(parsed, "decrypt_cipher", "aes-256-cbc") or "aes-256-cbc"
        scan_pii = bool(getattr(parsed, "scan_pii", False))

        if parsed.config:
            with open(parsed.config, "r", encoding="utf-8") as f:
                cfg_dict = json.load(f)
            rules = [AssertionRule(**r) for r in cfg_dict.get("assertion_rules", [])]
            config = VerificationConfig(
                database_type=cfg_dict.get("database_type", "sqlite"),
                backup_path=cfg_dict["backup_path"],
                expected_tables=cfg_dict.get("expected_tables", []),
                assertion_rules=rules,
                host=cfg_dict.get("host"),
                port=cfg_dict.get("port"),
                user=cfg_dict.get("user"),
                password=cfg_dict.get("password"),
                drop_on_completion=cfg_dict.get("drop_on_completion", True),
                decrypt_passphrase=passphrase or cfg_dict.get("decrypt_passphrase"),
                decrypt_cipher=cipher or cfg_dict.get("decrypt_cipher", "aes-256-cbc"),
                scan_pii=scan_pii or cfg_dict.get("scan_pii", False),
                max_rpo_hours=getattr(parsed, "max_rpo_hours", None) or cfg_dict.get("max_rpo_hours"),
                replica_paths=getattr(parsed, "replica", []) or cfg_dict.get("replica_paths", []),
                max_replication_lag_hours=getattr(parsed, "max_replication_lag_hours", None) or cfg_dict.get("max_replication_lag_hours"),
                require_321_redundancy=bool(getattr(parsed, "require_321", False)) or cfg_dict.get("require_321_redundancy", False),
                verify_manifest_path=getattr(parsed, "verify_manifest", None) or cfg_dict.get("verify_manifest_path"),
                verify_integrity=bool(getattr(parsed, "verify_integrity", False)) or cfg_dict.get("verify_integrity", False),
            )
            out_dir = cfg_dict.get("output_dir", parsed.out)
        else:
            if not parsed.backup:
                print("Error: --backup is required when --config is not specified.", file=sys.stderr)
                return 1

            tables = [t.strip() for t in parsed.tables.split(",")] if parsed.tables else []
            config = VerificationConfig(
                database_type=parsed.type,
                backup_path=parsed.backup,
                expected_tables=tables,
                host=parsed.host,
                port=parsed.port,
                user=parsed.user,
                decrypt_passphrase=passphrase,
                decrypt_cipher=cipher,
                scan_pii=scan_pii,
                max_rpo_hours=getattr(parsed, "max_rpo_hours", None),
                replica_paths=getattr(parsed, "replica", []),
                max_replication_lag_hours=getattr(parsed, "max_replication_lag_hours", None),
                require_321_redundancy=bool(getattr(parsed, "require_321", False)),
                verify_manifest_path=getattr(parsed, "verify_manifest", None),
                verify_integrity=bool(getattr(parsed, "verify_integrity", False)),
            )
            out_dir = parsed.out

        temp_download_dir = None
        if config.backup_path.startswith("s3://"):
            from drillops.storage.providers import S3CompatibleStorageProvider, parse_s3_uri
            print(f"Resolving remote cloud backup from: {config.backup_path}")
            bucket, key = parse_s3_uri(config.backup_path)
            s3_prov = S3CompatibleStorageProvider(
                bucket_name=bucket,
                endpoint_url=getattr(parsed, "s3_endpoint_url", None),
                region_name=getattr(parsed, "s3_region", None),
            )
            temp_download_dir = tempfile.mkdtemp(prefix="drillops_s3_")
            try:
                downloaded_file = s3_prov.download_object(key, temp_download_dir)
                config.backup_path = downloaded_file
            except Exception as e:
                print(f"Error downloading backup from {config.backup_path}: {e}", file=sys.stderr)
                if temp_download_dir and os.path.exists(temp_download_dir):
                    shutil.rmtree(temp_download_dir, ignore_errors=True)
                return 1

        print("================================================================")
        print("  DRILLOPS: Automated Disaster Recovery Drill Engine v0.1.0     ")
        print("================================================================")
        print(f"Target Backup: {config.backup_path}")
        print(f"Database Engine: {config.database_type}")
        print(f"Expected Tables: {config.expected_tables or 'None specified'}")
        print("Executing restore drill into isolated sandbox...")

        runner = DrillRunner()
        summary, assertions, artifacts = runner.run_drill(config, output_dir=out_dir)

        print("\n---------------------- DRILL RESULTS ---------------------------")
        print(f"Certificate ID:      {summary.certificate_id}")
        print(f"Overall Status:      {summary.overall_status}")
        print(f"Restore Time (RTO):  {summary.restore_duration_sec:.4f} seconds")
        if summary.backup_timestamp:
            print(f"Backup Created:      {summary.backup_timestamp}")
        if summary.backup_age_hours is not None:
            print(f"Backup Age (RPO):    {summary.backup_age_hours:.2f} hours")
        if summary.rpo_sla_hours is not None:
            status_sym = "✅" if summary.rpo_status == "COMPLIANT" else "❌"
            print(f"RPO SLA Freshness:   {summary.rpo_sla_hours:.1f} hours ({status_sym} {summary.rpo_status})")
        print(f"Backup SHA-256:      {summary.backup_sha256[:16]}...{summary.backup_sha256[-8:]}")
        print(f"Backup Size:         {summary.backup_size_bytes:,} bytes")
        print(f"Total Assertions:    {summary.total_assertions}")
        print(f"Passed:              {summary.passed_assertions}")
        print(f"Failed:              {summary.failed_assertions}")

        if summary.failure_reasons:
            print("\nFailures:")
            for reason in summary.failure_reasons:
                print(f"  ❌ {reason}")

        if artifacts:
            print("\nCompliance Artifacts Generated:")
            print(f"  📄 Markdown Certificate: {artifacts.get('markdown')}")
            print(f"  📋 JSON Audit Record:    {artifacts.get('json')}")
            if artifacts.get("html"):
                print(f"  📊 Executive HTML Report:{artifacts.get('html')}")

        # Notification dispatch
        if parsed.config and "notifications" in cfg_dict:
            notify_cfg = NotificationConfig.from_env_or_dict(cfg_dict.get("notifications"))
        else:
            notify_cfg = NotificationConfig(
                webhook_url=parsed.notify_webhook,
                slack_webhook_url=parsed.notify_slack,
                discord_webhook_url=parsed.notify_discord,
                pagerduty_routing_key=parsed.notify_pagerduty,
                vanta_webhook_url=parsed.notify_vanta,
                drata_webhook_url=parsed.notify_drata,
            )
        dispatcher = NotificationDispatcher(notify_cfg)
        notif_results = dispatcher.dispatch_all(summary, assertions)
        if notif_results:
            print("\nNotifications Dispatched:")
            for nr in notif_results:
                status_str = "SUCCESS" if nr.success else f"FAILED ({nr.error})"
                print(f"  🔔 [{nr.channel}] {nr.target_url} -> {status_str}")

        print("================================================================\n")

        if temp_download_dir and os.path.exists(temp_download_dir):
            shutil.rmtree(temp_download_dir, ignore_errors=True)

        return 0 if summary.overall_status == "PASSED" else 1

    elif parsed.command == "serve":
        from drillops.server.app import run_dashboard_server
        print(f"Starting DrillOps Compliance Dashboard on http://{parsed.host}:{parsed.port}")
        print(f"Reading certificates from: {parsed.out}")
        httpd = run_dashboard_server(host=parsed.host, port=parsed.port, cert_dir=parsed.out)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server.")
        return 0

    elif parsed.command == "watch":
        from drillops.daemon.watcher import DrillWatcher
        from drillops.storage.providers import get_storage_provider
        provider = get_storage_provider(
            parsed.dir,
            endpoint_url=getattr(parsed, "endpoint_url", None),
            region_name=getattr(parsed, "region", None),
        )
        config = VerificationConfig(
            database_type=parsed.type,
            backup_path="",
            max_rpo_hours=getattr(parsed, "max_rpo_hours", None),
        )
        watcher = DrillWatcher(provider=provider, config=config, output_dir=parsed.out)
        print(f"DrillWatcher monitoring '{parsed.dir}' (Engine: {parsed.type})...")
        if parsed.once:
            res = watcher.check_and_run_once()
            if res:
                print(f"Drill completed: Status={res.overall_status}, Cert={res.certificate_id}")
            else:
                print("No new backups to verify.")
            return 0
        else:
            print("Running in continuous poll mode (every 60s)... Press Ctrl+C to stop.")
            try:
                while True:
                    watcher.check_and_run_once()
                    import time
                    time.sleep(60)
            except KeyboardInterrupt:
                print("\nWatcher stopped.")
            return 0

    elif parsed.command == "orchestrate":
        from drillops.daemon.orchestrator import MultiTargetOrchestrator, OrchestratorConfig
        print(f"Loading multi-target configuration from: {parsed.config}")
        orch_cfg = OrchestratorConfig.from_json_file(parsed.config)
        orch = MultiTargetOrchestrator(orch_cfg)
        print(f"DrillOps Orchestrator initialized with {len(orch_cfg.targets)} target(s).")
        results = orch.run_all_once()
        print("\n---------------- ORCHESTRATOR PASS COMPLETE --------------------")
        for target_name, res in results.items():
            if res:
                print(f"  Target '{target_name}': {res.overall_status} (Cert: {res.certificate_id}, RTO: {res.restore_duration_sec:.2f}s)")
            else:
                print(f"  Target '{target_name}': No new backup or check completed.")
        print("================================================================\n")
        return 0

    elif parsed.command == "demo":
        from drillops.demo.interactive import InteractiveDemoRunner
        demo_runner = InteractiveDemoRunner()
        demo_runner.run_demo(output_dir=parsed.out)
        return 0

    elif parsed.command == "license":
        from drillops.licensing import LicenseValidator
        validator = LicenseValidator()
        valid, info, error = validator.validate_key(parsed.key)
        print("================================================================")
        print("  DRILLOPS LICENSE STATUS                                       ")
        print("================================================================")
        if not valid:
            print(f"  Status:         ❌ INVALID / EXPIRED")
            print(f"  Error:          {error}")
            return 1
        else:
            print(f"  Status:         🟢 VALID")
            print(f"  License ID:     {info.license_id}")
            print(f"  Tier:           {info.tier.value.upper()}")
            print(f"  Licensed To:    {info.customer_name} <{info.customer_email}>")
            print(f"  Issued At:      {info.issued_at}")
            print(f"  Expires:        {info.expires_at or 'Perpetual'}")
            print(f"  Max Targets:    {info.max_targets if info.max_targets > 0 else 'Unlimited'}")
            print(f"  Active Features: {', '.join(info.features)}")
        print("================================================================\n")
        return 0

    elif parsed.command == "audit-pack":
        from drillops.compliance.audit_pack import AuditPackGenerator
        print(f"Generating SOC2 Audit Pack from '{parsed.cert_dir}'...")
        generator = AuditPackGenerator(parsed.cert_dir)
        zip_path = generator.export_pack_zip(
            output_zip_path=parsed.out,
            days=parsed.days,
            company_name=parsed.company,
        )
        certs = generator.load_certificates(days=parsed.days)
        metrics = generator.calculate_metrics(certs)
        print(f"✅ Audit Dossier created successfully: {zip_path}")
        print(f"   Total Drills:    {metrics.total_drills}")
        print(f"   Pass Rate:       {metrics.success_rate_pct}%")
        print(f"   Avg RTO:         {metrics.avg_rto_seconds}s")
        print(f"   Assertions:      {metrics.passed_assertions}/{metrics.total_assertions}")
        return 0

    elif parsed.command == "generate-backup":
        from drillops.generator.synthetic import SyntheticDataGenerator
        print(f"Generating synthetic {parsed.engine} backup ({parsed.records} records, corrupt_mode={parsed.corrupt_mode})...")
        gen = SyntheticDataGenerator()
        if parsed.engine == "sqlite":
            res = gen.generate_sqlite_file(
                output_path=parsed.out,
                num_records=parsed.records,
                corrupt_mode=parsed.corrupt_mode if parsed.corrupt_mode != "none" else None,
            )
        elif parsed.engine == "mysql":
            res = gen.generate_mysql_sql(
                output_path=parsed.out,
                num_records=parsed.records,
                compress_gzip=parsed.compress,
                corrupt_mode=parsed.corrupt_mode if parsed.corrupt_mode != "none" else None,
            )
        else:
            res = gen.generate_postgres_sql(
                output_path=parsed.out,
                num_records=parsed.records,
                compress_gzip=parsed.compress,
                corrupt_mode=parsed.corrupt_mode if parsed.corrupt_mode != "none" else None,
            )
        print(f"✅ Generated: {res['output_path']} ({res['file_size']:,} bytes)")
        print(f"   SHA-256:   {res['sha256']}")
        print(f"   Tables:    {', '.join(res['tables'])}")
        return 0

    elif parsed.command == "notify-test":
        from drillops.models import DrillSummary
        summary = DrillSummary(
            certificate_id="DRC-TESTNOTIFY01",
            timestamp="2026-10-09T12:00:00Z",
            database_type="postgres",
            backup_filename="test_backup.sql.gz",
            backup_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            backup_size_bytes=1048576,
            restore_duration_sec=0.142,
            total_assertions=5,
            passed_assertions=5,
            failed_assertions=0,
            overall_status="PASSED",
        )
        cfg = NotificationConfig(webhook_secret=parsed.secret)
        dispatcher = NotificationDispatcher(cfg)
        print(f"Sending test notification ({parsed.type}) to {parsed.webhook}...")
        if parsed.type == "slack":
            res = dispatcher.send_slack(parsed.webhook, summary)
        elif parsed.type == "discord":
            res = dispatcher.send_discord(parsed.webhook, summary)
        elif parsed.type == "pagerduty":
            res = dispatcher.send_pagerduty(parsed.webhook, summary)
        elif parsed.type == "vanta":
            res = dispatcher.send_vanta(parsed.webhook, summary)
        elif parsed.type == "drata":
            res = dispatcher.send_drata(parsed.webhook, summary)
        else:
            res = dispatcher.send_generic_webhook(parsed.webhook, summary, [])

        if res.success:
            print(f"✅ Notification delivered successfully (Status {res.status_code})")
            return 0
        else:
            print(f"❌ Notification failed: {res.error}", file=sys.stderr)
            return 1

    elif parsed.command == "checklist":
        from dataclasses import asdict
        from drillops.compliance.checklist import SOC2ChecklistEvaluator

        evaluator = SOC2ChecklistEvaluator(cert_dir=parsed.cert_dir)
        if parsed.json:
            controls = evaluator.evaluate(company=parsed.company)
            print(json.dumps([asdict(c) for c in controls], indent=2))
        else:
            evaluator.print_terminal(company=parsed.company)

        if parsed.out:
            md_content = evaluator.to_markdown(company=parsed.company)
            os.makedirs(os.path.dirname(os.path.abspath(parsed.out)), exist_ok=True)
            with open(parsed.out, "w", encoding="utf-8") as f:
                f.write(md_content)
            print(f"📄 Saved SOC2 Disaster Recovery Audit Checklist to: {parsed.out}")
        return 0

    elif parsed.command == "badge":
        from drillops.compliance.badge import ComplianceBadgeGenerator
        gen = ComplianceBadgeGenerator(cert_dir=parsed.cert_dir)
        status = gen.get_badge_status()

        if parsed.shields_json:
            print(json.dumps(gen.generate_shields_json(), indent=2))
        elif parsed.markdown:
            badge_path = parsed.out or "./drillops_badge.svg"
            print(gen.generate_markdown(badge_path=badge_path))
        else:
            svg_content = gen.generate_svg()
            if parsed.out:
                os.makedirs(os.path.dirname(os.path.abspath(parsed.out)), exist_ok=True)
                with open(parsed.out, "w", encoding="utf-8") as f:
                    f.write(svg_content)
                print(f"🛡️  Generated DR Compliance SVG Badge: {parsed.out}")
                print(f"   Status: {status['label']}: {status['message']} ({status['color']})")
                print(f"   Embed:  {gen.generate_markdown(badge_path=parsed.out)}")
            else:
                print(svg_content)
        return 0

    elif parsed.command == "doctor":
        from dataclasses import asdict
        from drillops.system.doctor import SystemDoctor

        doc = SystemDoctor(cert_dir=parsed.cert_dir)
        if parsed.json:
            checks = doc.run_diagnostics()
            healthy = doc.is_healthy(checks)
            print(json.dumps({
                "healthy": healthy,
                "checks": [asdict(c) for c in checks],
            }, indent=2))
            return 0 if healthy else 1
        else:
            return doc.print_report()

    elif parsed.command == "systemd":
        from drillops.system.systemd import SystemdServiceGenerator

        unit = SystemdServiceGenerator.generate_service_unit(
            user=parsed.user,
            working_dir=parsed.dir,
            command_args=parsed.cmd,
        )
        if parsed.out:
            os.makedirs(os.path.dirname(os.path.abspath(parsed.out)), exist_ok=True)
            with open(parsed.out, "w", encoding="utf-8") as f:
                f.write(unit)
            print(f"📄 Saved systemd service unit to: {parsed.out}")
            print("\nTo install as a persistent Linux background service:")
            print(f"  sudo cp {parsed.out} /etc/systemd/system/drillops.service")
            print("  sudo systemctl daemon-reload")
            print("  sudo systemctl enable --now drillops")
        else:
            print(unit)
        return 0

    elif parsed.command == "metrics":
        from drillops.monitoring.metrics import PrometheusMetricsExporter

        exporter = PrometheusMetricsExporter(certificates_dir=parsed.cert_dir)
        if parsed.json:
            metrics_dict = exporter.collect_metrics()
            print(json.dumps(metrics_dict, indent=2))
        else:
            text = exporter.generate_prometheus_exposition()
            if parsed.out:
                exporter.write_metrics_file(parsed.out)
                print(f"📊 Saved Prometheus metrics to: {parsed.out}")
            else:
                sys.stdout.write(text)
        return 0

    elif parsed.command == "scan-pii":
        from drillops.assertions.pii_scanner import PIIScanner
        from drillops.storage.archive import ArchiveProcessor

        passphrase = getattr(parsed, "decrypt_passphrase", None) or os.environ.get("DRILLOPS_DECRYPT_PASSPHRASE")
        tables = [t.strip() for t in parsed.tables.split(",")] if parsed.tables else None

        config = VerificationConfig(
            database_type=parsed.type,
            backup_path=parsed.backup,
            expected_tables=tables or [],
            decrypt_passphrase=passphrase,
        )

        runner = DrillRunner()
        with tempfile.TemporaryDirectory(prefix="drillops_scan_pii_") as work_dir:
            try:
                payload_path = ArchiveProcessor.prepare_archive(
                    config.backup_path,
                    work_dir,
                    decrypt_passphrase=passphrase,
                )
                engine = runner.create_engine(config, work_dir)
                engine.setup_ephemeral_db()
                try:
                    engine.restore_dump(payload_path)
                    scanner = PIIScanner(engine)
                    findings = scanner.scan_all_tables(max_rows_per_table=parsed.max_rows, tables=tables)

                    if parsed.json:
                        output_data = {
                            "backup_path": parsed.backup,
                            "clean": len(findings) == 0,
                            "findings_count": len(findings),
                            "findings": [
                                {
                                    "table": f.table,
                                    "column": f.column,
                                    "finding_type": f.finding_type,
                                    "severity": f.severity,
                                    "count": f.count,
                                    "sample_redacted": f.sample_redacted,
                                    "description": f.description,
                                }
                                for f in findings
                            ],
                        }
                        print(json.dumps(output_data, indent=2))
                    else:
                        print(scanner.format_terminal_report(findings))

                    return 0 if len(findings) == 0 else 1
                finally:
                    engine.teardown()
            except Exception as e:
                print(f"Error during PII scan: {e}", file=sys.stderr)
                return 1

    elif parsed.command == "check-rpo":
        from drillops.core.rpo_auditor import RPOAuditor

        report = RPOAuditor.audit_rpo(
            parsed.backup,
            max_rpo_hours=parsed.max_rpo_hours,
        )

        if parsed.json:
            print(json.dumps({
                "backup_path": report.backup_path,
                "backup_timestamp": report.backup_timestamp.isoformat(),
                "backup_timestamp_source": report.backup_timestamp_source,
                "backup_age_seconds": report.backup_age_seconds,
                "backup_age_hours": report.backup_age_hours,
                "max_rpo_hours": report.max_rpo_hours,
                "is_compliant": report.is_compliant,
                "margin_hours": report.margin_hours,
                "status": report.status,
            }, indent=2))
        else:
            print(RPOAuditor.format_terminal_report(report))

        return 0 if report.is_compliant else 1

    elif parsed.command == "check-redundancy":
        from drillops.core.redundancy_auditor import RedundancyAuditor

        report = RedundancyAuditor.audit(
            primary_location=parsed.primary,
            replica_locations=parsed.replica,
            max_replication_lag_hours=parsed.max_lag_hours,
            require_321=parsed.require_321,
            s3_endpoint_url=getattr(parsed, "s3_endpoint_url", None),
            s3_region=getattr(parsed, "s3_region", None),
        )

        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            status_badge = "🟢 COMPLIANT" if report.status == "COMPLIANT" else "🔴 NON-COMPLIANT"
            print("\n========================================================")
            print(f" 🛡️  DrillOps 3-2-1 Backup Redundancy Audit: {status_badge}")
            print("========================================================")
            print(f"Primary:     {report.primary_location} ({report.primary_copy.storage_type}, {report.primary_copy.size_bytes:,} bytes)")
            print(f"SHA-256:     {report.primary_copy.sha256}")
            print(f"Replicas:    {len(report.replicas)} evaluated")
            for idx, rep in enumerate(report.replicas, 1):
                parity_mark = "✅ MATCH" if rep.sha256 == report.primary_copy.sha256 else "❌ MISMATCH"
                offsite_mark = " (Offsite)" if rep.is_offsite else " (Local)"
                print(f"  [{idx}] {rep.location}{offsite_mark}: {parity_mark}")
                if not rep.healthy:
                    print(f"      Error: {rep.error_message}")
            print("--------------------------------------------------------")
            print(f"Total Copies: {report.total_copies_count} (3-2-1 requirement: >=3)")
            print(f"Media Types:  {len(report.distinct_media_types)} ({', '.join(report.distinct_media_types)})")
            print(f"Offsite:      {report.offsite_copies_count} copies")
            print(f"3-2-1 Rule:   {'✅ SATISFIED' if report.is_321_compliant else '❌ NOT SATISFIED'}")
            print(f"Parity:       {'✅ ALL REPLICAS MATCH PRIMARY' if report.checksum_parity else '❌ CHECKSUM MISMATCH'}")
            if report.max_replication_lag_hours is not None:
                lag_h = report.observed_replication_lag_seconds / 3600.0
                lag_state = '❌ BREACHED' if report.replication_lag_breached else '✅ WITHIN SLA'
                print(f"Replication:  {lag_h:.2f}h lag (SLA: {report.max_replication_lag_hours}h) -> {lag_state}")
            print(f"Summary:      {report.summary}")
            print("========================================================\n")

        is_success = (report.status == "COMPLIANT") or (not parsed.require_321 and report.checksum_parity and not report.replication_lag_breached)
        return 0 if is_success else 1

    elif parsed.command == "check-integrity":
        from drillops.storage.integrity import IntegrityAuditor

        if getattr(parsed, "generate_manifest", False):
            man_path = IntegrityAuditor.generate_manifest(parsed.backup, output_path=parsed.manifest)
            print(f"✅ Generated SHA-256 manifest at: {man_path}")
            return 0

        report = IntegrityAuditor.audit(parsed.backup, manifest_path=parsed.manifest)
        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            status_badge = "🟢 VERIFIED" if report.status == "VERIFIED" else "🔴 CORRUPTED"
            print("\n========================================================")
            print(f" 🛡️  DrillOps Backup Integrity Audit: {status_badge}")
            print("========================================================")
            print(f"Target:      {report.filepath}")
            print(f"Size:        {report.size_bytes:,} bytes")
            print(f"Format:      {report.archive_format.upper()}")
            print(f"SHA-256:     {report.sha256}")
            print(f"Stream:      {'✅ HEALTHY (No bit-rot or truncation)' if report.stream_valid else '❌ CORRUPTED / TRUNCATED'}")
            if report.manifest_found:
                m_mark = "✅ MATCH" if report.manifest_matches else "❌ MISMATCH"
                print(f"Manifest:    {report.manifest_path} -> {m_mark}")
            else:
                print("Manifest:    None specified or found alongside backup")
            print(f"Details:     {report.details}")
            print("========================================================\n")

        return 0 if not report.corruption_detected else 1

    elif parsed.command == "report":
        from drillops.compliance.report_generator import ExecutiveReportGenerator

        if not os.path.isfile(parsed.cert):
            print(f"Error: Certificate file not found: {parsed.cert}", file=sys.stderr)
            return 1

        with open(parsed.cert, "r", encoding="utf-8") as f:
            cert_data = json.load(f)

        out_path = parsed.out
        if not out_path:
            base, _ = os.path.splitext(parsed.cert)
            out_path = f"{base}.html"

        saved_path = ExecutiveReportGenerator.save_report(
            output_path=out_path,
            summary=cert_data,
            assertions=cert_data.get("assertions", []),
            company_name=parsed.company,
        )

        if parsed.json:
            print(json.dumps({
                "certificate_id": cert_data.get("certificate_id"),
                "status": cert_data.get("overall_status"),
                "report_path": saved_path,
            }, indent=2))
        else:
            print(f"✅ Executive DR Audit Report generated: {saved_path}")

        return 0

    elif parsed.command == "check-pitr":
        from drillops.engines.pitr_validator import PITRValidator

        report = PITRValidator.audit(
            wal_directory=parsed.wal_dir,
            expected_size_mb=parsed.wal_size_mb,
        )

        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(PITRValidator.format_terminal_report(report))

        return 0 if report.is_continuous else 1

    elif parsed.command == "check-binlog":
        from drillops.engines.binlog_validator import BinlogValidator

        report = BinlogValidator.audit(
            binlog_directory=parsed.binlog_dir,
            prefix=getattr(parsed, "prefix", None),
        )

        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(BinlogValidator.format_terminal_report(report))

        return 0 if report.is_continuous else 1

    return 0



if __name__ == "__main__":
    sys.exit(main())
