# SOC 2 Type II & ISO 27001 Disaster Recovery Audit Evidence Dossier Guide

> **Target Audience**: Compliance Officers, Information Security Leads, VPs of Engineering, Site Reliability Engineers (SREs), and Third-Party SOC 2 / ISO 27001 Auditors.  
> **Tooling**: [DrillOps](https://github.com/redintDev/drillops) CLI, GitHub Actions, AWS S3 / Cloudflare R2, and Compliance Platforms (Vanta, Drata, Secureframe).  
> **Governing Standards**: 
> - **AICPA SOC 2 Type II**: Trust Services Criteria **CC9.1** (Testing backup media restore capability), **CC7.4** (Incident response and recovery procedures), **CC6.1** & **CC6.6** (Encryption at rest and boundary integrity).
> - **ISO/IEC 27001:2022**: Control **A.8.13** (Information Backup) & Control **A.8.14** (Redundancy of Information Processing Facilities).
> - **HIPAA Security Rule**: **§ 164.308(a)(7)(ii)(A)** (Data backup plan) & **§ 164.308(a)(7)(ii)(B)** (Disaster recovery testing procedures).

---

## 1. Executive Summary & Auditor Requirements

Modern SOC 2 Type II and ISO 27001 auditors no longer accept screenshots of backup cron jobs or AWS S3 bucket listings as evidence of disaster recovery capability.

Under **AICPA Trust Services Criterion CC9.1**:
> *"The entity tests backup media to determine whether it is capable of being restored; tests of backup media are conducted periodically."*

Under **ISO/IEC 27001:2022 Control A.8.13**:
> *"Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup."*

### What Auditors Require:
1. **Empirical Proof of Restoration**: Evidence that backup snapshots were fully decompressed and restored into a working database engine—not merely verified for file readability.
2. **Measured Recovery Time Objective (RTO)**: Clocked, sub-second telemetry proving actual restore duration against defined SLAs.
3. **Data Integrity & Schema Validation**: Automated assertions confirming that core tables exist, row counts match expectations, and schemas have not drifted.
4. **Cryptographic Chain of Custody**: Cryptographic hashes (SHA-256) matching the original backup artifact in object storage to the restored payload, guaranteeing zero tampering.
5. **Periodic Cadence (Type II Window)**: Continuous, repeatable restore drills throughout the 3-month to 12-month SOC 2 Type II audit window.

DrillOps automates this entire lifecycle, converting raw backup archives into signed, auditor-ready evidence dossiers in seconds.

---

## 2. The DrillOps Audit Evidence Package Architecture

When running `drillops audit-pack`, DrillOps aggregates historical drill certificates from your isolated sandbox drills into an immutable, portable ZIP archive:

```bash
drillops audit-pack \
  --cert-dir ./certificates \
  --out-zip ./soc2_audit_dossier.zip \
  --days 90 \
  --company "Acme Global, Inc."
```

### Archive Structure
```
soc2_audit_dossier.zip
├── AUDIT_DOSSIER.md          # Markdown executive summary & SLA performance table
├── AUDIT_DOSSIER.html        # Styled, print-ready HTML dossier for PDF export
├── SOC2_DR_CHECKLIST.md      # 8-control SOC 2 / ISO 27001 readiness evaluation & sign-off sheet
├── manifest.json             # Cryptographic manifest with SHA-256 digests and scores
└── certificates/             # Immutable JSON certificates and HTML reports per drill
    ├── drill_cert_drc-a1b2c3.json
    ├── drill_cert_drc-a1b2c3.html
    ├── drill_cert_drc-d4e5f6.json
    └── drill_cert_drc-d4e5f6.html
```

---

## 3. Dossier Components & Auditor Verification

### 1. `AUDIT_DOSSIER.html` (Printable Executive Report)
A self-contained HTML evidence dossier styled with Tailwind CSS. It contains:
- **Attestation Statement**: Formal declaration of autonomous sandbox execution in compliance with CC6.1, CC7.1, CC7.4, and A.8.13.
- **Disaster Recovery KPI & SLA Grid**:
  - Total restore drills executed in the audit window.
  - Drill success rate (target: 100%).
  - Average and maximum recorded Recovery Time Objective (RTO).
  - Number of data integrity assertions evaluated and passed.
- **Cryptographic Verification Chain**: Complete table of every restore drill, recording Certificate ID, UTC timestamp, database engine, backup filename, SHA-256 digest, actual RTO, and pass/fail status.
- **Auditor Print Button**: Formatted for standard browser `Print to PDF` (margins, clean borders, page breaks).

### 2. `SOC2_DR_CHECKLIST.md` (8-Control Readiness Matrix)
Evaluates your disaster recovery program across 8 core controls:

| Control ID | Standard Criteria | Control Title | Automation Status |
| :--- | :--- | :--- | :--- |
| **DR-01** | SOC 2 CC9.1 / ISO 27001 A.12.3.1 | Documented DR Policy & RTO/RPO SLAs | Measured via actual restore telemetry |
| **DR-02** | SOC 2 CC9.1 / HIPAA § 164.308 | Automated Backup Generation & Offsite Storage | Monitored via S3/R2 watcher daemon |
| **DR-03** | SOC 2 CC7.4 / ISO 27001 A.12.3.1 | Cryptographic Backup Integrity (SHA-256) | Computed before ephemeral restore |
| **DR-04** | SOC 2 CC9.1 / ISO 27001 A.12.3.1 | Continuous Sandbox Restoration Drills | Automated ephemeral engine restore |
| **DR-05** | SOC 2 CC7.4 / SOC 2 CC9.1 | Post-Restore Data Integrity Assertions | Declarative table & count validation |
| **DR-06** | SOC 2 CC8.1 | Schema Drift & Column Migration Validation | Automated schema diff detection |
| **DR-07** | SOC 2 CC9.1 / ISO 27001 A.12.3.1 | Automated Incident Alerting on Failure | Instant Slack/Discord/PagerDuty alerts |
| **DR-08** | SOC 2 CC9.1 / Auditor Packaging | Consolidated Auditor Evidence Packaging | Turnkey `drillops audit-pack` ZIP bundle |

### 3. `manifest.json` (Tamper-Evident Ledger)
Enables auditors to programmatically verify that none of the certificates have been altered:
```json
{
  "dossier_version": "1.0",
  "organization": "Acme Global, Inc.",
  "generated_at_utc": "2026-11-17T02:00:00.000000+00:00",
  "compliance_standards": [
    "SOC2_TYPE_II_CC7.4",
    "ISO_27001_A.8.13",
    "SOC2_TYPE_II_CC9.1"
  ],
  "metrics": {
    "total_drills": 12,
    "passed_drills": 12,
    "failed_drills": 0,
    "success_rate_pct": 100.0,
    "avg_rto_seconds": 1.42,
    "max_rto_seconds": 3.85,
    "total_assertions": 48
  },
  "soc2_dr_checklist": {
    "readiness_score_pct": 100.0,
    "verified_controls": 8,
    "total_controls": 8
  },
  "certificates": [
    {
      "certificate_id": "DRC-9F8E7D6C5B4A",
      "filename": "drill_cert_drc-9f8e7d6c5b4a.json",
      "sha256": "4a5e6d...b1c2",
      "status": "PASSED"
    }
  ]
}
```

---

## 4. How Auditors Verify the Evidence

Auditors can execute this 3-step verification checklist:

1. **Verify Manifest Digest**: Check that each JSON certificate in `certificates/` matches the SHA-256 hash recorded in `manifest.json`:
   ```bash
   sha256sum certificates/drill_cert_*.json
   ```
2. **Match Backup Provenance**: Match the recorded `backup_sha256` digest in any certificate against the object storage ETag / SHA-256 header in AWS S3 or Cloudflare R2:
   ```bash
   aws s3api head-object --bucket my-backups --key prod-db-2026-11-15.sql.gz
   ```
3. **Verify Semantic Assertions**: Review the `assertions` block in the certificate to confirm that critical business tables and row count thresholds passed.

---

## 5. Integrating with Vanta, Drata, and Secureframe

### Vanta Integration
1. In Vanta, navigate to **Tests** &rarr; **Data Backup & Recovery**.
2. Select the control: *"Database backups are restored and tested periodically"*.
3. Upload `AUDIT_DOSSIER.html` (or PDF) as the annual/quarterly evidence artifact.
4. Set the verification frequency to match your CI/CD drill schedule (Weekly or Monthly).

### Drata Integration
1. In Drata, open **Controls** &rarr; **DCF-74: Backup Restoration Test**.
2. Under **Evidence**, click **Add Evidence Document**.
3. Select `AUDIT_DOSSIER.html` and `SOC2_DR_CHECKLIST.md`.
4. Drata automatically tags the upload with timestamp and uploader attribution.

### Secureframe Integration
1. In Secureframe, navigate to **Evidence Library** &rarr; **Data Backup Restoration Tests**.
2. Attach `soc2_audit_dossier.zip` directly to the active audit period.

---

## 6. Automating Audit Pack Generation in CI/CD

Add this step to your scheduled GitHub Actions workflow to generate and store audit dossiers automatically on the 1st of every month:

```yaml
name: Monthly SOC 2 Disaster Recovery Audit Dossier
on:
  schedule:
    - cron: '0 0 1 * *'  # 1st of every month at midnight UTC
  workflow_dispatch:

jobs:
  audit-dossier:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install DrillOps
        run: pip install "git+https://github.com/redintDev/drillops.git"

      - name: Run Ephemeral Database Restore Drill
        uses: redintDev/drillops@v0.2
        with:
          backup-path: ./backups/prod_backup.sql.gz
          database-type: postgres
          expected-tables: users,organizations,billing_subscriptions
          output-dir: ./certificates

      - name: Compile 90-Day SOC 2 Audit Pack
        run: |
          drillops audit-pack \
            --cert-dir ./certificates \
            --out-zip ./soc2_audit_dossier.zip \
            --days 90 \
            --company "Acme Global, Inc."

      - name: Upload Audit Dossier Artifact
        uses: actions/upload-artifact@v4
        with:
          name: soc2-dr-audit-dossier
          path: ./soc2_audit_dossier.zip
          retention-days: 365
```

---

## 7. Frequently Asked Auditor Questions (Auditor FAQ)

#### Q: How does DrillOps verify data without risking production?
**A:** DrillOps restores backups into **ephemeral, sandboxed database instances** on isolated compute. No connection strings to production databases are ever accepted or stored. All sandbox databases are completely wiped upon drill completion.

#### Q: Does DrillOps check for data corruption or just exit codes?
**A:** DrillOps executes semantic assertion queries on the restored tables (e.g. verifying table schema contracts, checking row counts > 0, and scanning for missing columns). A backup that restores without errors but yields 0 rows or missing tables fails the drill.

#### Q: How is Recovery Time Objective (RTO) calculated?
**A:** RTO measurement begins the millisecond decompression starts and ends only when all data integrity assertions complete successfully. The measured duration is recorded in the certificate metrics to two decimal places.

#### Q: Does the restore test expose sensitive PII or credentials?
**A:** DrillOps includes a built-in pre-flight and post-restore PII scanner (`--scan-pii`). It alerts if unmasked credit card numbers (PANs), Social Security Numbers (SSNs), private keys, or API tokens are detected in unencrypted database dumps.

#### Q: Can our team run an interactive demonstration before buying?
**A:** Yes. Running `drillops demo` runs an end-to-end interactive 4-step disaster recovery drill locally in under 10 seconds, generating sample certificates, HTML reports, and a live SOC 2 DR Readiness Score.

---

*Authored by the DrillOps Autonomous Engineering & Compliance Team. For licensing inquiries, volume support, or compliance questions, contact [abdellatifaamrani4@gmail.com](mailto:abdellatifaamrani4@gmail.com).*
