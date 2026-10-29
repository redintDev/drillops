# 🛠️ DrillOps Integration & Configuration Examples

This directory provides production-ready templates, configurations, and automation manifests for integrating DrillOps into your infrastructure.

---

## Directory Index

| Example | Description | Typical Use Case |
| :--- | :--- | :--- |
| **[`github_actions/`](./github_actions/)** | Automated CI/CD disaster recovery drill workflows | Nightly or weekly automated backup restore verification in GitHub Actions |
| **[`targets/`](./targets/)** | Multi-database declarative configuration file (`drillops_targets.json`) | Orchestrating drills across multiple PostgreSQL, MySQL, and SQLite databases |
| **[`systemd/`](./systemd/)** | Linux `systemd` service unit file | Running DrillOps as a continuous background daemon on Linux servers / VPS |

---

## 1. GitHub Actions Scheduled Drill (`examples/github_actions/`)

Copy [`examples/github_actions/disaster_recovery_scheduled_drill.yml`](./github_actions/disaster_recovery_scheduled_drill.yml) into your `.github/workflows/` directory.

- Runs on a nightly cron schedule (`0 2 * * *`).
- Pulls database backup artifact or dump file.
- Executes `redintDev/drillops@v0.2` restore drill.
- Validates tables, measures RTO/RPO SLA compliance, and runs PII leakage scan.
- Uploads cryptographically signed SOC 2 compliance certificates as workflow artifacts.

---

## 2. Multi-Target Declarative Orchestrator (`examples/targets/`)

See [`examples/targets/drillops_targets.example.json`](./targets/drillops_targets.example.json).

Run a multi-target audit pass:
```bash
drillops orchestrate --config examples/targets/drillops_targets.example.json --once
```

---

## 3. Systemd Watcher Daemon (`examples/systemd/`)

See [`examples/systemd/drillops-watcher.service`](./systemd/drillops-watcher.service).

Install and enable the service on Linux:
```bash
sudo cp examples/systemd/drillops-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now drillops-watcher
```
