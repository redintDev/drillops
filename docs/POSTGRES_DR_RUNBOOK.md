# PostgreSQL Disaster Recovery Runbook & Automated Verification Guide

> **Target Audience**: PostgreSQL DBAs, Site Reliability Engineers (SREs), Infrastructure Leads, and SOC 2 / ISO 27001 Compliance Officers.  
> **Tooling**: PostgreSQL 14/15/16/17, `pg_dump`, `pg_restore`, `psql`, and [DrillOps](https://github.com/redintDev/drillops).  
> **Standard Compliance**: SOC 2 Trust Services Criterion CC9.1, ISO/IEC 27001:2022 A.8.14 (Redundancy of Information Processing Facilities), HIPAA § 164.308(a)(7)(ii)(B).

---

## 1. The Core Problem: The "Schrödinger's Backup" Trap

Almost every engineering organization runs automated backups:
```bash
# Nightly pg_dump cron job
pg_dump -Fc -h db.prod.internal -U postgres -d main_db > /backups/main_db_$(date +%F).dump
```

However, **a backup that finishes with exit code `0` is NOT proof of recoverability**. Real-world outages frequently reveal:
1. **Silent Table Truncation**: Backups taken during partial maintenance windows missing partition tables or active write buffers.
2. **PostgreSQL Version Incompatibilities**: Custom types (`pgcrypto`, `postgis`, `timescaledb`, `hstore`) missing from newer major versions of the target restore instance.
3. **Unmeasured RTO (Recovery Time Objective)**: When a real outage occurs, the restore takes 14 hours instead of the SLA-mandated 2 hours due to index recreation and IOPS bottlenecks.
4. **Schema Drift**: Application migrations added non-nullable columns without default values, rendering restored dumps unable to boot with current application code.
5. **Auditor Scramble**: SOC 2 CC9.1 requires annual or quarterly documented proof of backup restoration. Engineers spend 8–16 hours manually restoring dumps to staging to take screenshots.

---

## 2. Automated PostgreSQL DR Verification Architecture

An automated disaster recovery drill must meet four criteria:
- **Zero Production Risk**: Restores must run in ephemeral, isolated environments with zero write access to production.
- **Sub-Second RTO Measurement**: Timestamps must be measured from the start of decompression to the final row assertion.
- **Deep Semantic Validation**: Do not just check table existence; verify table row counts and schema integrity.
- **Cryptographic Evidence Dossier**: Generate tamper-evident, auditor-ready JSON and Markdown certificates with SHA-256 backup digests.

```
┌────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│   Backup Artifact      │      │    Ephemeral Restore    │      │  Semantic Assertions &  │
│  (Local, S3, or R2)    ├─────►│    Isolation Engine     ├─────►│  RTO SLA Measurement    │
│  SHA-256 Checksummed   │      │  PostgreSQL 16 / SQLite │      │  Row counts & Contracts │
└────────────────────────┘      └─────────────────────────┘      └────────────┬────────────┘
                                                                              │
                                                                 ┌────────────▼────────────┐
                                                                 │ Cryptographic Dossier   │
                                                                 │ SOC 2 CC9.1 Audit Pack  │
                                                                 │ JSON Cert + SHA-256     │
                                                                 └─────────────────────────┘
```

---

## 3. Step-by-Step Implementation

### Step 1: Install DrillOps
DrillOps provides a standalone, zero-dependency Python CLI for ephemeral restore drills:

```bash
# 1-Line Turnkey Installer (Linux, macOS, WSL)
curl -sSL https://raw.githubusercontent.com/redintDev/drillops/main/install.sh | bash

# Or via pip directly from GitHub:
pip install "git+https://github.com/redintDev/drillops.git"
```

### Step 2: Run an Ephemeral Verification Drill

Run a complete automated drill against a PostgreSQL dump (`.dump`, `.sql`, or `.sql.gz`):

```bash
# Verify local PostgreSQL backup with semantic table assertion
drillops verify \
  --backup /var/backups/postgres/prod_db_2026-11-12.sql.gz \
  --type postgres \
  --tables users,organizations,payments,audit_log \
  --max-rto-seconds 300 \
  --out /var/log/drillops/certificates
```

For cloud storage (AWS S3, Cloudflare R2, or MinIO):
```bash
drillops verify \
  --backup s3://my-backup-vault/prod_db_latest.sql.gz \
  --type postgres \
  --tables users,subscriptions \
  --s3-endpoint-url "https://<account_id>.r2.cloudflarestorage.com" \
  --out ./certificates
```

### Step 3: Inspect the Output Certificate

Upon successful restore, DrillOps generates an auditor-grade JSON and Markdown certificate:

```json
{
  "certificate_id": "CERT-20261112-9A4B",
  "status": "PASS",
  "engine": "postgres",
  "backup_source": "s3://my-backup-vault/prod_db_latest.sql.gz",
  "backup_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "rto_seconds": 42.18,
  "rto_sla_seconds": 300.0,
  "sla_met": true,
  "tables_verified": [
    {"name": "users", "rows": 142850, "status": "VERIFIED"},
    {"name": "organizations", "rows": 1240, "status": "VERIFIED"},
    {"name": "payments", "rows": 894200, "status": "VERIFIED"}
  ],
  "compliance_mapping": {
    "soc2": "CC9.1",
    "iso27001": "A.8.14",
    "hipaa": "164.308(a)(7)(ii)(B)"
  },
  "timestamp": "2026-11-12T09:30:00Z"
}
```

---

## 4. Turnkey CI/CD Workflow (GitHub Actions)

Add this workflow to your repository to verify backups on a nightly schedule and automatically package audit dossiers:

```yaml
# .github/workflows/nightly-dr-drill.yml
name: Nightly Database DR Verification

on:
  schedule:
    - cron: '0 3 * * *'  # 03:00 UTC daily
  workflow_dispatch:

jobs:
  verify-restore:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run DrillOps DR Verification
        uses: redintDev/drillops@v0.2.2
        with:
          backup-path: "s3://my-backup-bucket/postgres/latest.sql.gz"
          engine-type: "postgres"
          required-tables: "users,teams,billing_invoices"
          max-rto-seconds: "180"
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.BACKUP_RO_AWS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.BACKUP_RO_AWS_SECRET }}
          AWS_REGION: "us-east-1"

      - name: Upload SOC 2 Evidence Dossier
        uses: actions/upload-artifact@v4
        with:
          name: soc2-dr-evidence-${{ github.sha }}
          path: certificates/
          retention-days: 365
```

---

## 5. SOC 2 CC9.1 Audit Readiness Checklist

When an external auditor asks for your Disaster Recovery evidence:
1. **Provide the Automated Pipeline Link**: Point the auditor to your scheduled GitHub Actions run history.
2. **Export the Audit Dossier ZIP**:
   ```bash
   drillops audit-pack --cert-dir ./certificates --out-zip ./soc2_dossier.zip
   ```
3. **Verify SHA-256 Signatures**: Demonstrate that the tested backup's SHA-256 hash matches the storage archive digest.

---

## 6. Commercial Support & Enterprise Licensing

For multi-target orchestrated daemons, automated Vanta/Drata compliance API webhooks, and air-gapped offline enterprise license keys:
- **Project Repository**: [https://github.com/redintDev/drillops](https://github.com/redintDev/drillops)
- **Interactive Simulator**: [https://redintdev.github.io/drillops/](https://redintdev.github.io/drillops/)
- **Commercial Inquiry & Enterprise Keys**: Email [`abdellatifaamrani4@gmail.com`](mailto:abdellatifaamrani4@gmail.com)
