# SafeMigrate GitHub Action Example

This directory contains turnkey GitHub Actions workflow definitions for integrating **SafeMigrate** into CI/CD pipelines.

---

## Quickstart

Copy `safemigrate_pr_check.yml` into your repository at:
```bash
.github/workflows/safemigrate.yml
```

Whenever a developer opens a Pull Request modifying `.sql` migration files, SafeMigrate will:
1. **Statically audit** every DDL statement for dangerous lock modes (`AccessExclusiveLock`, `ShareLock`, table rewrites).
2. **Emit inline PR annotations** highlighting the exact line number of unsafe statements directly in the GitHub diff.
3. **Publish a Step Summary** markdown report with risk classification and downtime mitigations.
4. **Suggest zero-downtime rewrites** as a unified diff codeblock (e.g. adding `CONCURRENTLY` or `NOT VALID`).

---

## Action Inputs & Configuration

The composite action is hosted at `redintDev/drillops/safemigrate@main`.

| Input | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | String | `migrations` | Path to SQL migration file or directory to scan. |
| `dialect` | String | `postgresql` | Database dialect: `postgresql` or `mysql`. |
| `strict` | Boolean | `false` | When `true`, fails CI on `MEDIUM` warnings (e.g. missing `lock_timeout`). |
| `publish-summary` | Boolean | `true` | Publishes markdown audit table to GitHub Step Summary. |
| `suggest-fixes` | Boolean | `true` | Appends zero-downtime diff to Step Summary if hazards are detected. |

---

## Action Outputs

You can condition downstream deployment steps on SafeMigrate outputs:

| Output | Description |
| :--- | :--- |
| `lint-status` | `PASSED` if all migrations are safe, `FAILED` if blocking hazards detected. |
| `critical-hazards` | Total count of `CRITICAL` severity hazards (e.g. volatile default rewrites). |
| `high-hazards` | Total count of `HIGH` severity hazards (e.g. unindexed foreign keys). |

---

## Multi-Dialect / Monorepo Matrix Example

If your repository manages migrations across multiple database services:

```yaml
name: "SafeMigrate Matrix Check"

on:
  pull_request:
    paths: ["services/**/migrations/**"]

jobs:
  audit-migrations:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - name: "Auth Service (PostgreSQL)"
            path: "services/auth/migrations"
            dialect: "postgresql"
          - name: "Billing Service (MySQL)"
            path: "services/billing/migrations"
            dialect: "mysql"
    steps:
      - uses: actions/checkout@v4
      - name: Audit ${{ matrix.name }}
        uses: redintDev/drillops/safemigrate@main
        with:
          path: ${{ matrix.path }}
          dialect: ${{ matrix.dialect }}
          suggest-fixes: "true"
```
