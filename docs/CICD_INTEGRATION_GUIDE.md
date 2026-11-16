# Continuous Disaster Recovery Verification in CI/CD Pipelines

> **Target Audience**: DevOps Engineers, Site Reliability Engineers (SREs), Platform Architects, and SOC 2 / ISO 27001 Compliance Officers.  
> **Supported Platforms**: GitHub Actions, GitLab CI/CD, Bitbucket Pipelines, CircleCI, and Kubernetes CronJobs.  
> **Tooling**: [DrillOps](https://github.com/redintDev/drillops) (`v0.2.2 GA`), PostgreSQL, MySQL/MariaDB, SQLite, AWS S3, Cloudflare R2, MinIO.  
> **Compliance Standards**: SOC 2 Trust Services Criterion CC9.1, ISO/IEC 27001:2022 A.8.14, HIPAA § 164.308(a)(7)(ii)(B).

---

## 1. Why Continuous DR in CI/CD?

In modern cloud environments, infrastructure and application schemas change continuously:
- **Application Migrations Drift**: Prisma, TypeORM, Alembic, or Django migrations add non-nullable columns without defaults.
- **Backup Pipeline Failures**: Cron jobs silently exit with code 0 while producing empty or truncated dump files.
- **Auditor Evidence Scramble**: SOC 2 Type II and ISO 27001 auditors require regular documented proof of backup restoration.

Instead of paying high manual engineering costs to restore databases in staging once a quarter, **Continuous DR Verification executes automated, ephemeral restore drills on a nightly or weekly schedule inside existing CI/CD pipelines**.

```
┌────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
│ Scheduled CI/CD Trigger│      │ Ephemeral Runner / Pod  │      │  Semantic Assertions &  │
│ (Nightly at 02:00 UTC) ├─────►│ Decompress & Sandbox    ├─────►│  Sub-Second RTO SLA     │
│ Ingest Latest S3/R2 DB │      │ PostgreSQL / MySQL / SQL│      │  Row Counts & Contracts │
└────────────────────────┘      └─────────────────────────┘      └────────────┬────────────┘
                                                                              │
                                                                 ┌────────────▼────────────┐
                                                                 │ CI/CD Artifact Archive  │
                                                                 │ SOC 2 CC9.1 Audit Pack  │
                                                                 │ 365-Day Retained Dossier│
                                                                 └─────────────────────────┘
```

---

## 2. GitHub Actions Integration

### Recipe A: Official Turnkey GitHub Action (`redintDev/drillops@v0.2.2`)

The easiest drop-in workflow using the official composite action:

```yaml
# .github/workflows/database-dr-drill.yml
name: Scheduled Database DR Verification

on:
  schedule:
    - cron: '0 3 * * *'  # Run every night at 03:00 UTC
  workflow_dispatch:      # Enable manual triggers from GitHub UI

jobs:
  verify-dr:
    name: Verify Database Restore & SLA
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run DrillOps Verification
        uses: redintDev/drillops@v0.2.2
        with:
          backup-path: "s3://production-backups-vault/postgres/prod_db_latest.sql.gz"
          engine-type: "postgres"
          required-tables: "users,organizations,billing_invoices,audit_log"
          max-rto-seconds: "180"
          output-dir: "certificates"
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.BACKUP_RO_AWS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.BACKUP_RO_AWS_SECRET }}
          AWS_REGION: "us-east-1"
          DRILLOPS_LICENSE_KEY: ${{ secrets.DRILLOPS_LICENSE_KEY }} # Optional: unlocks Pro/Enterprise features

      - name: Upload SOC 2 Evidence Dossier Artifact
        uses: actions/upload-artifact@v4
        with:
          name: soc2-dr-dossier-${{ github.sha }}
          path: certificates/
          retention-days: 365
```

### Recipe B: Standalone CLI with Slack / PagerDuty Alerting

For complex pipelines requiring pre-flight checks, custom decryption, or PII scanning:

```yaml
# .github/workflows/advanced-dr-drill.yml
name: Advanced PostgreSQL & MySQL DR Verification

on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 02:00 UTC
  workflow_dispatch:

jobs:
  verify-all:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Database Binaries & DrillOps
        run: |
          sudo apt-get update && sudo apt-get install -y postgresql-client mysql-client
          curl -sSL https://raw.githubusercontent.com/redintDev/drillops/main/install.sh | bash
          source ~/.bashrc || true

      - name: Run Pre-Flight Diagnostics
        run: drillops doctor

      - name: Download & Verify Production Postgres Backup
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.BACKUP_RO_AWS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.BACKUP_RO_AWS_SECRET }}
        run: |
          drillops verify \
            --backup s3://company-backups/postgres/daily.sql.gz \
            --type postgres \
            --tables users,teams,subscriptions \
            --max-rto-seconds 120 \
            --scan-pii \
            --max-rpo-hours 24 \
            --out ./certificates

      - name: Generate Executive Compliance Report (HTML)
        run: |
          drillops report --cert-dir ./certificates --out ./dr_executive_report.html
          drillops audit-pack --cert-dir ./certificates --out-zip ./soc2_audit_pack.zip

      - name: Upload Compliance Dossier
        uses: actions/upload-artifact@v4
        with:
          name: executive-dr-report
          path: |
            dr_executive_report.html
            soc2_audit_pack.zip
          retention-days: 365
```

---

## 3. GitLab CI/CD (`.gitlab-ci.yml`)

GitLab CI users can run scheduled pipeline triggers using containerized runners with automatic job artifact preservation:

```yaml
# .gitlab-ci.yml
stages:
  - disaster-recovery

verify_database_dr:
  stage: disaster-recovery
  image: python:3.12-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends postgresql-client curl ca-certificates
    - pip install --no-cache-dir "git+https://github.com/redintDev/drillops.git"
    - drillops doctor
  script:
    - mkdir -p certificates
    - drillops verify
        --backup $S3_BACKUP_URI
        --type postgres
        --tables users,tenants,orders,audit_events
        --max-rto-seconds 240
        --s3-endpoint-url $S3_ENDPOINT_URL
        --out ./certificates
    - drillops report --cert-dir ./certificates --out ./certificates/executive_dr_report.html
    - drillops audit-pack --cert-dir ./certificates --out-zip ./certificates/soc2_gitlab_dossier.zip
  variables:
    AWS_ACCESS_KEY_ID: $BACKUP_VAULT_KEY_ID
    AWS_SECRET_ACCESS_KEY: $BACKUP_VAULT_SECRET
    AWS_DEFAULT_REGION: "us-east-1"
  artifacts:
    name: "soc2-dr-evidence-${CI_COMMIT_SHORT_SHA}"
    when: always
    expire_in: 365 days
    paths:
      - certificates/
```

---

## 4. Bitbucket Pipelines (`bitbucket-pipelines.yml`)

For organizations hosting source code on Atlassian Bitbucket:

```yaml
# bitbucket-pipelines.yml
image: python:3.12

pipelines:
  custom:
    scheduled-dr-drill:
      - step:
          name: Automated Disaster Recovery Verification
          caches:
            - pip
          script:
            - apt-get update && apt-get install -y postgresql-client
            - pip install "git+https://github.com/redintDev/drillops.git"
            - drillops doctor
            - drillops verify --backup $BACKUP_S3_URI --type postgres --tables users,accounts --out ./certs
            - drillops report --cert-dir ./certs --out ./certs/executive_report.html
            - drillops audit-pack --cert-dir ./certs --out-zip ./certs/soc2_dossier.zip
          artifacts:
            - certs/**
```

---

## 5. CircleCI (`.circleci/config.yml`)

CircleCI scheduled workflow with Docker executor:

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  verify-dr:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Install DB Clients & DrillOps
          command: |
            sudo apt-get update && sudo apt-get install -y postgresql-client
            pip install "git+https://github.com/redintDev/drillops.git"
      - run:
          name: Run DrillOps Verification Drill
          command: |
            mkdir -p ./certificates
            drillops verify \
              --backup "$S3_BACKUP_URL" \
              --type postgres \
              --tables users,organizations \
              --max-rto-seconds 180 \
              --out ./certificates
            drillops audit-pack --cert-dir ./certificates --out-zip ./certificates/soc2_audit_pack.zip
      - store_artifacts:
          path: ./certificates
          destination: dr-evidence

workflows:
  version: 2
  nightly_dr_drill:
    triggers:
      - schedule:
          cron: "0 4 * * *"
          filters:
            branches:
              only:
                - main
    jobs:
      - verify-dr
```

---

## 6. Kubernetes In-Cluster CronJob (`dr-verify-cronjob.yaml`)

For regulated environments (HIPAA, FedRAMP, banking) where database backups cannot leave the private Virtual Private Cloud (VPC), run DrillOps directly as an in-cluster Kubernetes CronJob:

```yaml
# k8s/dr-verify-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: drillops-nightly-verification
  namespace: data-platform
spec:
  schedule: "0 2 * * *"  # Nightly at 02:00 UTC
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 30
  failedJobsHistoryLimit: 7
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: drillops
              image: python:3.12-slim
              command: ["/bin/bash", "-c"]
              args:
                - |
                  apt-get update && apt-get install -y postgresql-client curl ca-certificates
                  pip install --no-cache-dir "git+https://github.com/redintDev/drillops.git"
                  drillops verify \
                    --backup /vault/backups/daily_prod.sql.gz \
                    --type postgres \
                    --tables users,organizations,transactions \
                    --max-rto-seconds 300 \
                    --out /evidence
                  drillops report --cert-dir /evidence --out /evidence/dr_report.html
              volumeMounts:
                - name: backup-storage
                  mountPath: /vault/backups
                  readOnly: true
                - name: evidence-storage
                  mountPath: /evidence
          volumes:
            - name: backup-storage
              persistentVolumeClaim:
                claimName: prod-backups-pvc
            - name: evidence-storage
              persistentVolumeClaim:
                claimName: soc2-evidence-pvc
```

---

## 7. How to Present CI/CD Output to SOC 2 Auditors

When audit season arrives:
1. **Direct Pipeline Link**: Provide your auditor read-only access to your GitHub/GitLab scheduled CI run history. Every run displays:
   - Green `PASS` status.
   - Restored database engine version.
   - Precise RTO duration benchmark.
   - SHA-256 backup digest matching storage manifests.
2. **Download Retained Artifact**: Download the zipped evidence dossier (`soc2_audit_pack.zip`) retained by your CI platform.
3. **Attestation Signature**: Present the cryptographic JSON certificate containing the Ed25519 signature confirming zero tampering.

---

## 8. Commercial Licensing in CI/CD Environments

DrillOps features an **offline-first, zero-DRM architecture**. In CI/CD runners:
- No telephone-home network calls.
- No central license server dependencies.
- Simply set `DRILLOPS_LICENSE_KEY` as a secret environment variable in GitHub Secrets, GitLab CI Variables, or Kubernetes Secrets.

To acquire a Pro ($79/yr) or Enterprise ($199/yr) license token:
- **Web Portal & Trial Token**: [https://redintdev.github.io/drillops/](https://redintdev.github.io/drillops/)
- **Commercial Pricing**: [https://github.com/redintDev/drillops/blob/main/docs/COMMERCIAL_PRICING.md](https://github.com/redintDev/drillops/blob/main/docs/COMMERCIAL_PRICING.md)
- **Direct Order Inquiries**: Email [`abdellatifaamrani4@gmail.com`](mailto:abdellatifaamrani4@gmail.com)
