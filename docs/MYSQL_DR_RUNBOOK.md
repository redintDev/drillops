# MySQL & MariaDB Disaster Recovery Runbook & Automated Verification Guide

> **Target Audience**: MySQL & MariaDB DBAs, Site Reliability Engineers (SREs), DevOps Leads, and SOC 2 / ISO 27001 Compliance Officers.  
> **Supported Engines**: MySQL 5.7, 8.0, 8.4 LTS, MariaDB 10.5 through 11.4+.  
> **Tooling**: `mysqldump`, `mariadb-dump`, MySQL Binary Logs (`mysqlbinlog`), and [DrillOps](https://github.com/redintDev/drillops).  
> **Standard Compliance**: SOC 2 Trust Services Criterion CC9.1, ISO/IEC 27001:2022 Control A.8.14 (Redundancy of Information Processing Facilities), HIPAA § 164.308(a)(7)(ii)(B).

---

## 1. The Core Problem: The MySQL Backup Trap

Virtually every production environment has an automated MySQL dump routine running in cron or scheduled jobs:

```bash
# Standard automated mysqldump cron command
mysqldump -h db.prod.internal -u dbadmin -p"$DB_PASS" \
  --single-transaction --quick app_production > /backups/app_prod_$(date +%F).sql
```

However, **an archive file exiting with return code `0` is NOT proof of disaster recoverability**. Real-world outages frequently reveal catastrophic hidden deficits:

1. **Silent MyISAM / Non-Transactional Lock Failures**: If legacy tables exist in MyISAM or memory engines, `--single-transaction` does NOT guarantee read consistency, resulting in fractured foreign keys and corrupted state.
2. **Collation & Strict SQL Mode Incompatibilities**: Restoring a dump taken with `NO_ZERO_DATE` or older `utf8mb3` charsets onto modern MySQL 8.0/8.4 instances with strict SQL modes (`ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES`) fails midway through multi-gigabyte SQL statements.
3. **Broken Binary Log Sequences for PITR**: A full logical backup is useless for Point-in-Time Recovery (PITR) if the corresponding binary logs (`binlog`) have missing sequence indices, truncated records, or missing magic headers.
4. **Catastrophic RTO Overshoot**: Logical SQL text dumps require single-threaded re-execution of every `INSERT` statement and index rebuild. A 50 GB backup that takes 20 minutes to dump can take 12 hours to restore, breaching customer SLAs and board expectations.
5. **Auditor Evidence Scramble**: SOC 2 CC9.1 mandates documented, periodic proof of restoration. Teams waste days manually spinning up ephemeral staging instances to capture terminal screenshots.

---

## 2. Automated MySQL DR Verification Architecture

A resilient, audit-compliant disaster recovery protocol requires continuous, automated verification meeting four key pillars:

- **Isolated Sandbox Execution**: Restores run in ephemeral test databases without touching production network interfaces.
- **Microsecond RTO/RPO Measurement**: Precise timing from gzip decompression to table assertion completion, benchmarking actual recovery speeds.
- **Binary Log Continuity Auditing**: Pre-flight validation of binary log sequences before replaying transactions up to a specific timestamp.
- **Cryptographic Audit Packaging**: Tamper-evident SHA-256 manifests and signed compliance certificates satisfying third-party auditors.

```
┌────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│   MySQL Backup Dump    │      │    Ephemeral Restore    │      │  Semantic Assertions &  │
│  (.sql / .sql.gz)      ├─────►│    Isolation Engine     ├─────►│  RTO SLA Measurement    │
│  SHA-256 Checksummed   │      │  MySQL 8.0 / MariaDB    │      │  Row counts & Contracts │
└────────────────────────┘      └─────────────────────────┘      └────────────┬────────────┘
                                                                              │
┌────────────────────────┐      ┌─────────────────────────┐                   │
│ Binary Log Chain       │      │ Pre-Flight PITR Audit   │                   │
│ (mysql-bin.00000X)     ├─────►│ Magic Header & Gap Check├───────────────────┤
└────────────────────────┘      └─────────────────────────┘                   │
                                                                 ┌────────────▼────────────┐
                                                                 │ Cryptographic Dossier   │
                                                                 │ SOC 2 CC9.1 Audit Pack  │
                                                                 │ JSON Cert + SHA-256     │
                                                                 └─────────────────────────┘
```

---

## 3. Step-by-Step Implementation

### Step 1: Install DrillOps

Install DrillOps via the official turnkey shell installer or directly from GitHub:

```bash
# 1-Line Turnkey Installer (Linux, macOS, WSL)
curl -sSL https://raw.githubusercontent.com/redintDev/drillops/main/install.sh | bash

# Or via pip
pip install "git+https://github.com/redintDev/drillops.git"
```

Verify your local environment and database binaries:

```bash
drillops doctor
```

---

### Step 2: Generate Safe, Consistent Production Dumps

Ensure production MySQL backup scripts include flags preventing table lockups and capturing metadata required for consistency:

```bash
# Recommended production backup command
mysqldump -h db.prod.internal -u backup_user -p"$BACKUP_PASS" \
  --single-transaction \
  --quick \
  --triggers \
  --routines \
  --events \
  --set-gtid-purged=OFF \
  --max-allowed-packet=512M \
  app_production | gzip -c > /var/backups/mysql/app_prod_$(date +%Y%m%d_%H%M%S).sql.gz
```

---

### Step 3: Run Automated Restore Drill

Execute an automated drill against the backup using `drillops verify`. DrillOps restores the dump into an ephemeral sandbox, measures RTO, and executes business assertions:

```bash
drillops verify \
  --backup /var/backups/mysql/app_prod_latest.sql.gz \
  --type mysql \
  --host 127.0.0.1 \
  --port 3306 \
  --user root \
  --password "$SANDBOX_ROOT_PASS" \
  --expected-tables users,organizations,transactions,audit_logs \
  --max-rto-sec 600 \
  --out ./certificates
```

Example Output:
```
======================================================================
  🛡️  DRILLOPS RESTORE DRILL VERIFICATION CERTIFICATE
======================================================================
  Certificate ID:    DRC-A1B2C3D4E5F6
  Database Engine:   MySQL 8.0.35 (InnoDB)
  Backup File:       app_prod_latest.sql.gz (48.2 MB)
  Payload SHA-256:   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Decompressed Size: 312.4 MB
  Restore Duration:  18.42s (SLA: < 600.0s) [PASSED]
  Expected Tables:   4/4 present (users, organizations, transactions, audit_logs)
  Overall Status:    🟢 PASSED (SLA Compliant)
======================================================================
```

---

### Step 4: Validate Point-in-Time Recovery (PITR) Binary Logs

A common failure mode in MySQL recovery occurs when replaying binary logs up to a specific transaction timestamp, only to discover missing sequence numbers or corrupted log headers.

Use `drillops check-binlog` to audit the binary log archive for continuous sequence indexes and valid magic headers (`\xfe\x62\x69\x6e`):

```bash
drillops check-binlog \
  --dir /var/backups/mysql/binlogs \
  --index /var/backups/mysql/binlogs/mysql-bin.index \
  --prefix mysql-bin \
  --max-gap-hours 1.0 \
  --json
```

If a binary log file is missing or truncated, DrillOps immediately flags the defect:
```json
{
  "status": "GAP_DETECTED",
  "missing_segments": ["mysql-bin.000042"],
  "error": "Sequence gap detected: missing segment mysql-bin.000042 between 000041 and 000043."
}
```

---

### Step 5: Audit Backup Freshness & RPO Compliance

Ensure your MySQL backup schedules meet organizational Recovery Point Objectives (RPO) under SOC 2 CC9.1 and HIPAA standards:

```bash
drillops check-rpo \
  --backup /var/backups/mysql/app_prod_latest.sql.gz \
  --max-rpo-hours 24.0 \
  --warn-threshold-hours 18.0
```

---

### Step 6: Scan for Sensitive PII & Credential Leaks

Before sharing database snapshots across teams or uploading evidence to third-party auditor portals, scan for unmasked credit cards, AWS credentials, and plaintext passwords:

```bash
drillops scan-pii \
  --backup /var/backups/mysql/app_prod_latest.sql.gz \
  --type mysql \
  --host 127.0.0.1 \
  --port 3306 \
  --user root \
  --password "$SANDBOX_ROOT_PASS" \
  --out pii_audit_report.json
```

---

### Step 7: Generate SOC 2 CC9.1 & ISO 27001 Auditor Evidence Dossier

When audit season arrives, compile 90+ days of historical restore certificates into a tamper-evident compliance ZIP package:

```bash
drillops audit-pack \
  --cert-dir ./certificates \
  --company "Your Organization Corp" \
  --days 90 \
  --out ./mysql_dr_audit_dossier.zip
```

The resulting package contains:
- `AUDIT_DOSSIER.md`: Executive summary with pass rates, average RTO trends, and SLA adherence.
- `AUDIT_DOSSIER.html`: Printable, styled compliance report ready for auditor submission.
- `manifest.json`: Cryptographic SHA-256 checksums of every underlying certificate file.
- `certificates/`: Raw immutable JSON and Markdown certificates for independent inspection.

---

## 4. Continuous CI/CD & Production Automation

### Option A: GitHub Actions (Turnkey CI Verification)

Automate restore drills on every release or nightly cron using the official composite action:

```yaml
name: Nightly MySQL Backup Drill
on:
  schedule:
    - cron: '0 3 * * *' # Every night at 03:00 UTC
  workflow_dispatch:

jobs:
  verify-backup:
    runs-on: ubuntu-latest
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
        ports:
          - 3306:3306
        options: --health-cmd="mysqladmin ping" --health-interval=10s --health-timeout=5s --health-retries=3

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Download latest backup from S3
        run: |
          aws s3 cp s3://my-corp-backups/mysql/latest.sql.gz ./latest.sql.gz

      - name: Run DrillOps Verification
        uses: redintDev/drillops@v0.2
        with:
          backup_path: ./latest.sql.gz
          database_type: mysql
          expected_tables: users,organizations,transactions,audit_logs
          max_rto_seconds: 300
```

---

### Option B: Linux Systemd Background Daemon

Run continuous directory or S3 bucket monitoring using a hardened Linux systemd service:

```bash
# Generate production systemd unit file
drillops systemd \
  --user agyagent \
  --exec-path /usr/local/bin/drillops \
  --config /etc/drillops/targets.json \
  --out /etc/systemd/system/drillops-watcher.service

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable --now drillops-watcher
```

---

## 5. Summary Compliance Checklist

| Requirement | Standard | DrillOps Automation Command |
| :--- | :--- | :--- |
| **Periodic Restore Drills** | SOC 2 CC9.1 / ISO 27001 A.8.14 | `drillops verify --type mysql` |
| **Point-in-Time Recovery (PITR)** | SOC 2 CC9.1 | `drillops check-binlog --index ...` |
| **RPO SLA Enforcement** | SOC 2 CC9.1 / HIPAA § 164.308 | `drillops check-rpo --max-rpo-hours 24` |
| **3-2-1 Offsite Redundancy** | ISO 27001 A.8.14 | `drillops check-redundancy` |
| **PII & Secret Sanitization** | SOC 2 CC6.1 / GDPR / PCI-DSS | `drillops scan-pii` |
| **Auditor Evidence Packaging** | SOC 2 Type II / ISO 27001 | `drillops audit-pack --out dossier.zip` |

---

*For enterprise support, multi-target orchestrators, and automated compliance webhook integrations, consult the [DrillOps Commercial Documentation](https://github.com/redintDev/drillops).*
