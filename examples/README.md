# 🛠️ DrillOps Integration & Configuration Examples

This directory provides production-ready templates, configurations, and automation manifests for integrating DrillOps into your infrastructure across CI/CD, Kubernetes, and Linux servers.

---

## Directory Index

| Example Manifest | Platform | Description & Typical Use Case |
| :--- | :--- | :--- |
| **[`github_actions/disaster_recovery_scheduled_drill.yml`](./github_actions/disaster_recovery_scheduled_drill.yml)** | GitHub Actions | Nightly automated database restore drill with RTO measurement and PII scanning |
| **[`github_actions/monthly_soc2_audit_pack_workflow.yml`](./github_actions/monthly_soc2_audit_pack_workflow.yml)** | GitHub Actions | Monthly 90-day SOC 2 & ISO 27001 audit evidence pack compiler and ZIP exporter |
| **[`gitlab_ci/.gitlab-ci.example.yml`](./gitlab_ci/.gitlab-ci.example.yml)** | GitLab CI/CD | Scheduled GitLab CI pipeline for containerized restore drills and artifact retention |
| **[`kubernetes/drillops-cronjob.example.yaml`](./kubernetes/drillops-cronjob.example.yaml)** | Kubernetes | In-cluster Kubernetes CronJob for air-gapped / VPC-isolated restore drills |
| **[`targets/drillops_targets.example.json`](./targets/drillops_targets.example.json)** | CLI Multi-Target | Declarative multi-database targets file for PostgreSQL, MySQL, and SQLite fleets |
| **[`systemd/drillops-watcher.service`](./systemd/drillops-watcher.service)** | Linux systemd | Hardened systemd service unit to run DrillOps as a continuous background daemon |

---

## 1. GitHub Actions Workflows (`examples/github_actions/`)

### Nightly Scheduled Drill
Copy [`examples/github_actions/disaster_recovery_scheduled_drill.yml`](./github_actions/disaster_recovery_scheduled_drill.yml) into `.github/workflows/`:
- Runs on a nightly schedule (`0 2 * * *`).
- Executes `redintDev/drillops@v0.2` drop-in action.
- Validates tables, measures sub-second RTO, enforces RPO freshness, scans for PII/secrets, and records certificates.

### Monthly SOC 2 Audit Pack Compiler
Copy [`examples/github_actions/monthly_soc2_audit_pack_workflow.yml`](./github_actions/monthly_soc2_audit_pack_workflow.yml) into `.github/workflows/`:
- Runs on the 1st of every month at midnight UTC (`0 0 1 * *`).
- Runs `drillops audit-pack` compiling `AUDIT_DOSSIER.md`, `AUDIT_DOSSIER.html`, `SOC2_DR_CHECKLIST.md`, and `manifest.json`.
- Uploads the complete ZIP dossier as a retained workflow artifact for external auditors.

---

## 2. GitLab CI/CD Pipeline (`examples/gitlab_ci/`)

Copy [`examples/gitlab_ci/.gitlab-ci.example.yml`](./gitlab_ci/.gitlab-ci.example.yml) into your repository root as `.gitlab-ci.yml`.
- Triggers on scheduled pipelines (`$CI_PIPELINE_SOURCE == "schedule"`).
- Uses `python:3.12-slim` container with PostgreSQL client.
- Stores certificates and audit dossiers in GitLab CI artifacts with 365-day retention.

---

## 3. Kubernetes In-Cluster CronJob (`examples/kubernetes/`)

For air-gapped, FedRAMP, or banking environments where backups cannot leave the private VPC:
```bash
kubectl apply -f examples/kubernetes/drillops-cronjob.example.yaml
```
- Mounts backup volume as read-only.
- Restores into an ephemeral sandbox without external network access.
- Saves certificates and audit dossiers to a persistent evidence PVC.

---

## 4. Multi-Target Declarative Orchestrator (`examples/targets/`)

See [`examples/targets/drillops_targets.example.json`](./targets/drillops_targets.example.json).

Run a multi-target audit pass across your database fleet:
```bash
drillops orchestrate --config examples/targets/drillops_targets.example.json --once
```

---

## 5. Systemd Watcher Daemon (`examples/systemd/`)

See [`examples/systemd/drillops-watcher.service`](./systemd/drillops-watcher.service).

Install and enable the continuous watcher daemon on Linux:
```bash
sudo cp examples/systemd/drillops-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now drillops-watcher
```
