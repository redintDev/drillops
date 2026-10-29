# 🛡️ DrillOps: Automated Database Restore Drill Runner & SOC2 Certifier

> *"An untested backup is not a backup—it is merely a wish."*

DrillOps is an autonomous database disaster recovery verification engine. It proves that database backups actually restore to completion *before* disaster strikes, measuring Recovery Time Objective (RTO) and compiling cryptographically signed, auditor-grade compliance evidence for SOC2 Type II, ISO 27001, and HIPAA audits.

---

## ⚡ Quickstart in 5 Seconds

Experience a full sandbox restore drill, defect detection cycle, and SOC2 audit dossier generation with a single command:

```bash
# Run the interactive guided demo
drillops demo
```

---

## 📦 Installation

```bash
# 1-Command Turnkey Installer (Linux, macOS, WSL)
curl -sSL https://raw.githubusercontent.com/redintDev/drillops/main/install.sh | bash

# Or install directly with pip from GitHub
pip install "git+https://github.com/redintDev/drillops.git"

# Or clone and install locally
git clone https://github.com/redintDev/drillops.git && cd drillops && pip install -e .
```

---

## 🚀 Key Commands

### 1. Verify a Single Backup (Local or Cloud S3 / Cloudflare R2)
```bash
# Verify local backup (PostgreSQL, MySQL, MariaDB, or SQLite)
drillops verify \
  --backup ./backups/prod_db.sql.gz \
  --type mysql \
  --tables users,organizations,transactions \
  --out ./certificates

# Or verify remote backup directly from AWS S3 or Cloudflare R2
drillops verify \
  --backup s3://my-backup-vault/postgres/prod_db.sql.gz \
  --type postgres \
  --tables users,organizations \
  --s3-endpoint-url "https://<account_id>.r2.cloudflarestorage.com"
```

### 2. Run the Automated Watcher Daemon (Local Directory or S3 Bucket)
```bash
# Continuously monitors local backup directory
drillops watch --dir /var/backups --type postgres --out ./certificates

# Or continuously poll an S3 / R2 bucket for new backup archives
drillops watch \
  --dir s3://my-backup-vault/postgres/ \
  --type postgres \
  --endpoint-url "https://<account_id>.r2.cloudflarestorage.com" \
  --out ./certificates
```

### 3. Launch Compliance Dashboard & API
```bash
# Starts embedded dark-mode dashboard on port 8787
drillops serve --port 8787
```

### 4. Generate SOC2 / ISO 27001 Evidence Dossier
```bash
# Aggregates certificates into printable HTML, Markdown, and manifest ZIP
drillops audit-pack --cert-dir ./certificates --out audit_dossier.zip --days 90
```

### 5. Multi-Target Declarative Orchestrator
```bash
# Orchestrate drills across multiple databases concurrently
drillops orchestrate --config drillops_targets.json --once
```

### 6. Inspect & Activate Offline Commercial Licenses
```bash
# Inspect current license state and active tier limits
drillops license info

# Verify an offline cryptographic license key token
drillops license verify --key "DRILLOPS-V2.eyJpZCI6IkxJQy...<sig>"

# Activate via environment variable:
export DRILLOPS_LICENSE_KEY="DRILLOPS-V2.eyJpZCI6IkxJQy...<sig>"
drillops license info
```
Generate free 14-day evaluation keys or request commercial Pro/Enterprise licenses at:
👉 **[https://redintdev.github.io/drillops/](https://redintdev.github.io/drillops/)**

### 7. Turnkey GitHub Action
Verify database restore drills automatically in your GitHub Actions CI/CD pipelines:
```yaml
- name: Verify Database Restore Drill & Certify SOC2
  uses: redintDev/drillops@v0.2.0 # Pinned release (or @v0.2, @main)
  with:
    backup-path: ./backups/production.dump
    database-type: postgres # postgres, mysql, mariadb, or sqlite
    expected-tables: users,orders,billing
    scan-pii: 'true'
    max-rpo-hours: '24'
    export-report: 'true'
    output-dir: ./certificates
```

### 8. SOC2 CC9.1 & ISO 27001 Audit Preparation Checklist
Evaluate disaster recovery readiness across 8 key SOC2/ISO audit controls and export audit-ready markdown reports:
```bash
# Terminal audit overview with readiness scoring
drillops checklist --cert-dir ./certificates --company "Acme Corp"

# Export auditor-ready Markdown report or structured JSON
drillops checklist --out ./SOC2_DR_CHECKLIST.md --company "Acme Corp"
drillops checklist --json
```

### 9. Disaster Recovery Compliance Badges
Generate cryptographic SVG badges and Shields.io JSON endpoints to showcase verified DR readiness in GitHub READMEs, status pages, and auditor trust portals:
```bash
# Generate standalone SVG badge
drillops badge --cert-dir ./certificates --out ./drillops_badge.svg

# Output Shields.io dynamic endpoint JSON or Markdown embed snippet
drillops badge --cert-dir ./certificates --shields-json
drillops badge --markdown --out ./drillops_badge.svg
```

### 10. System Pre-Flight Diagnostics (`drillops doctor`)
Run comprehensive environment and connectivity health checks before executing database restore drills:
```bash
# Terminal diagnostics report
drillops doctor

# Machine-readable JSON for monitoring and CI health checks
drillops doctor --json
```

### 11. Linux Systemd Background Service Generator (`drillops systemd`)
Generate hardened production systemd unit files to run DrillOps watcher daemons persistently across reboots:
```bash
# Generate service unit file
drillops systemd --cmd "watch --dir /var/backups --type postgres" --out ./drillops.service

# Install into systemd:
sudo cp ./drillops.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now drillops
```

### 12. Enterprise Compliance & Incident Integrations (Vanta, Drata, PagerDuty)
Automatically dispatch restore drill audit proofs directly to continuous compliance platforms or on-call paging systems:
```bash
# Verify backup and upload evidence directly to Vanta & Drata custom test webhooks
drillops verify \
  --backup ./backups/prod.sql.gz \
  --type postgres \
  --notify-vanta "https://api.vanta.com/v1/custom_tests/test-xxx/upload" \
  --notify-drata "https://public-api.drata.com/public/compliance/tests/dr-01"

# Test webhook integrations
drillops notify-test --type vanta --webhook "https://api.vanta.com/v1/custom_tests/test-xxx/upload"
drillops notify-test --type drata --webhook "https://public-api.drata.com/public/compliance/tests/dr-01"
```

### 13. Prometheus Metrics Exporter & Observability (`drillops metrics` / `/metrics`)
Export database restore drill health, compliance states, and RTO latency gauges directly to Prometheus, Grafana Agent, or Datadog:
```bash
# Export Prometheus text exposition metrics to stdout
drillops metrics --cert-dir ./certificates

# Export metrics directly to file for Prometheus node_exporter textfile collector
drillops metrics --cert-dir ./certificates --out /var/lib/node_exporter/textfile_collector/drillops.prom

# Output structured JSON metrics for custom monitoring agents
drillops metrics --cert-dir ./certificates --json
```
When running the embedded dashboard server (`drillops serve`), the `/metrics` endpoint is exposed out-of-the-box for Prometheus scrapers (`http://localhost:8787/metrics`).

### 14. Encrypted Backup Verification & Ephemeral Decryption (SOC2 CC6.1)
Verify database backups encrypted at rest using OpenSSL (`.enc`, `.aes`) or GPG (`.gpg`, `.pgp`) with automatic ephemeral decryption into isolated sandboxes and zero disk footprint:
```bash
# Verify an AES-256-CBC encrypted backup
drillops verify \
  --backup ./backups/prod.sql.gz.enc \
  --type postgres \
  --decrypt-passphrase "VaultMasterKey123!"

# Or supply passphrase via environment variable:
export DRILLOPS_DECRYPT_PASSPHRASE="VaultMasterKey123!"
drillops verify --backup ./backups/prod.dump.enc --type postgres
```
When an encrypted backup is verified, DrillOps automatically issues a verified **SOC2 CC6.1 Data at Rest Encryption** compliance assertion in the generated audit certificate.

### 15. Automated PII & Sensitive Data Leak Scanner (SOC2 CC6.1 / GDPR / PCI-DSS)
Ensure database backup copies and staging restores do not contain raw unmasked card numbers, SSNs, AWS access keys, private keys, or plaintext passwords:
```bash
# Scan backup sandbox for unmasked PII & secrets
drillops scan-pii --backup ./backups/prod.sql.gz --type postgres

# Output machine-readable JSON for compliance pipelines
drillops scan-pii --backup ./backups/staging.sql --type sqlite --json

# Or incorporate automatic PII sanitization verification directly into restore drills
drillops verify --backup ./backups/prod.dump --type postgres --scan-pii
```
When enabled during `drillops verify --scan-pii`, a formal **SOC2 CC6.1 Data Sanitization & Leak Prevention** assertion is evaluated and certified in the audit pack.

### 16. Recovery Point Objective (RPO) & Backup Freshness SLA Auditor (SOC2 CC9.1 / HIPAA)
Proves backup freshness and catches silent backup pipeline failures before auditors or disasters strike:
```bash
# Audit backup age and enforce Recovery Point Objective (RPO) SLA threshold (e.g. 24 hours)
drillops check-rpo --backup ./backups/prod.sql.gz --max-rpo-hours 24

# Output machine-readable JSON for automated monitoring checks
drillops check-rpo --backup ./backups/prod.dump --max-rpo-hours 6 --json

# Or enforce RPO SLA freshness directly during full restore drills
drillops verify --backup ./backups/prod.dump --type postgres --max-rpo-hours 24
```
When `--max-rpo-hours` is configured, DrillOps inspects dump headers, filename timestamps, and metadata to certify **SOC2 CC9.1 / HIPAA §164.308 / ISO 27001 A.12.3.1 RPO Freshness** compliance.

### 17. Automated 3-2-1 Backup Redundancy & Offsite Parity Auditor (SOC2 CC9.1 / ISO 27001)
Proves compliance with the gold standard 3-2-1 disaster recovery rule (3 copies of data, 2 distinct media types, 1 offsite copy):
```bash
# Audit primary backup against cold-storage replica (e.g. local vs AWS S3 / Cloudflare R2)
drillops check-redundancy \
  --primary ./backups/prod_backup.sql.gz \
  --replica s3://my-dr-bucket/backups/prod_backup.sql.gz \
  --max-lag-hours 24 \
  --require-321

# Output structured JSON for compliance monitors and CI/CD pipelines
drillops check-redundancy --primary ./backup.db --replica ./replica.db --json

# Enforce 3-2-1 redundancy directly during restore drill verification
drillops verify \
  --backup ./backups/prod.dump \
  --type postgres \
  --replica s3://dr-backup-vault/prod.dump \
  --require-321
```
When configured with `--replica`, DrillOps calculates cryptographic SHA-256 hashes across all copies, measures replication lag, verifies storage media isolation, and injects a formal **SOC2 CC9.1 3-2-1 Redundancy & Replica Parity** assertion into the audit certificate.

### 18. Cold-Storage Bit-Rot & Checksum Manifest Auditor
Detects silent bit flips, truncated downloads, and corrupted archive headers in cold storage:
```bash
# Inspect backup archive for stream corruption, truncation, or CRC32 errors
drillops check-integrity --backup ./backups/prod.sql.gz

# Verify backup against cryptographic manifest (.sha256 or SHA256SUMS)
drillops check-integrity --backup ./backups/prod.dump --manifest ./backups/SHA256SUMS

# Generate a SHA-256 manifest file alongside a verified backup
drillops check-integrity --backup ./backups/prod.sql.gz --generate-manifest

# Or enforce cold-storage integrity verification during restore drills
drillops verify --backup ./backups/prod.sql.gz --type postgres --verify-integrity
```

### 19. Executive Disaster Recovery Audit Report Generator (`drillops report`)
Produces standalone, publication-ready, CSS-styled HTML & PDF audit dossiers for executive sign-off and auditor review:
```bash
# Generate CISO executive disaster recovery report from certificate JSON
drillops report --cert ./certificates/drill_cert_xxx.json --out ./reports/executive_report.html --company "Acme Enterprise"

# Output structured metadata as JSON
drillops report --cert ./certificates/drill_cert_xxx.json --json
```
The executive report encapsulates the complete Disaster Recovery Triad:
- **Pillar 1: RTO (Speed)**: Measured restoration duration, schema construction, and query throughput.
- **Pillar 2: RPO (Freshness)**: Backup creation timestamp, age in hours, and SLA breach margin.
- **Pillar 3: 3-2-1 Redundancy**: Multi-copy tracking across storage tiers, media isolation, and offsite parity.
- **Security & Attestation**: SOC2 CC6.1 encryption at rest, PII leak scans, cold-storage bit-rot status, and CISO / Lead Engineer sign-off blocks.

### 20. PostgreSQL Point-in-Time Recovery (PITR) WAL Continuity Validator (`drillops check-pitr`)
Validates that continuous PostgreSQL Write-Ahead Log (WAL) archives stored on local disks or cloud storage buckets are unbroken and free of sequence gaps:
```bash
# Audit PostgreSQL WAL archive directory for sequence continuity
drillops check-pitr --wal-dir /var/lib/postgresql/wal_archive --wal-size-mb 16

# Output machine-readable JSON for monitoring alerts
drillops check-pitr --wal-dir /var/lib/postgresql/wal_archive --json
```
- Decodes 24-character hexadecimal WAL naming conventions (`Timeline + LogID + SegmentID`).
- Evaluates monotonic sequence continuity across log file rollovers (`...00FF` -> `...0100`).
- Validates 16MB standard segment sizing to detect truncated uploads and network write failures.
- Checks binary header magic bytes (`0xD07F` for PG16, `0xD07E` for PG15, `0xD07D` for PG14).

### 21. MySQL & MariaDB Binary Log (binlog) Continuity Validator (`drillops check-binlog`)
Validates that continuous MySQL / MariaDB binary log replication and point-in-time recovery streams are unbroken, properly indexed, and free of missing sequence segments:
```bash
# Audit MySQL / MariaDB binlog directory for sequence continuity
drillops check-binlog --binlog-dir /var/log/mysql/binlogs --prefix mysql-bin

# Output machine-readable JSON for monitoring alerts and CI/CD gates
drillops check-binlog --binlog-dir /var/log/mysql/binlogs --json
```
- Decodes standard sequential binlog naming conventions (`prefix.000001` -> `prefix.000002`).
- Detects non-contiguous index numbers, missing segments, and corrupt or truncated binlogs.
- Inspects 4-byte magic headers (`\xfebin` / `0xFE 0x62 0x69 0x6E`) for file integrity validation.
- Verifies `.index` catalog reconciliation when binlog index files exist on disk.

---

## 🏗️ Architecture

```
Backup Archive (.sql / .dump / .sql.gz / .enc / .gpg)
                │
                ├─────────────────────────────────────────┬───────────────────────────────┐
                ▼                                         ▼                               ▼
      ┌──────────────────┐                      ┌──────────────────┐            ┌──────────────────┐
      │ ArchiveProcessor │                      │    RPOAuditor    │            │RedundancyAuditor │
      │ (Decrypts,       │                      │ (Enforces CC9.1  │            │ (Enforces 3-2-1  │
      │  decompresses)   │                      │  freshness SLA)  │            │  offsite parity) │
      └─────────┬────────┘                      └─────────┬────────┘            └─────────┬────────┘
                │                                         │                               │
                ▼                                         │                               │
      ┌──────────────────┐                                │                               │
      │  RestoreEngine   │ (Sets up ephemeral sandbox,     │                               │
      │  (Postgres/MySQL │  executes restore, records RTO)│                               │
      │  SQLite/MariaDB) │                                │                               │
      └─────────┬────────┘                                │                               │
                │                                         │                               │
                ▼                                         │                               │
      ┌──────────────────┐                                │                               │
      │AssertionEvaluator│ (Runs table existence, volume, │                               │
      │ + PIIScanner     │  custom SQL rules, CC6.1 crypt,│                               │
      │ + IntegrityAudit │  CC9.1 RPO, & 3-2-1 redundancy)◄───────────────────────────────┘
      └─────────┬────────┘
                │
                ▼
      ┌──────────────────┐
      │AuditPackGenerator│ (Issues JSON/Markdown certificates & auditor ZIP dossier)
      └─────────┬────────┘
                │
                ▼
      ┌──────────────────┐
      │ NotificationHub  │ (Dispatches alerts & proofs: Vanta, Drata, PagerDuty, Slack, Discord, Webhooks)
      └──────────────────┘
                │
                ▼
      ┌──────────────────┐
      │ PrometheusMetric │ (Exposes /metrics & textfile exporter: RTO, RPO age, redundancy, SLA breach gauges)
      └──────────────────┘
```

---

## 💰 Commercial Tiers & Licensing

| Tier | Price | Highlights |
| :--- | :---: | :--- |
| **Community** | **$0** | Full CLI, SQLite, MySQL, MariaDB & Postgres restore engines, schema drift detection, 100% open-source |
| **Self-Hosted Pro** | **$79 / yr** | Embedded dashboard, watcher daemon, Slack/Discord alerts, Prometheus /metrics, SOC2 CC6.1 encrypted backup drills |
| **Enterprise** | **$199 / yr** | Unlimited targets, white-label compliance dossiers, Vanta/Drata automated evidence dispatch, automated PII & secret leak scanner, RPO freshness SLA enforcement, 3-2-1 redundancy & cold-storage bit-rot auditor, multi-target orchestrator, PITR WAL & MySQL binlog validators |

See [`docs/COMMERCIAL_PRICING.md`](docs/COMMERCIAL_PRICING.md) for full pricing details.

---

## 🧪 Testing

Run all 168 unit and integration tests:
```bash
source .venv/bin/activate
pytest projects/drillops/tests/
```
All 168 tests pass in < 20 seconds.

