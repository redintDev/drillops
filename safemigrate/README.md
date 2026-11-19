# SafeMigrate

> **Zero-Downtime Database Migration Linter & Safety Auditor**  
> Protect your production databases from lock queuing, table rewrites, and self-inflicted downtime in CI/CD pull requests.

[![Tests](https://img.shields.io/badge/tests-90%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

---

## ⚡ The Problem: Invisible Database Locks

A single database migration command that executes in milliseconds on a local SQLite or PostgreSQL database can bring down production under live traffic:

```sql
-- DANGEROUS: Takes AccessExclusiveLock, rewrites entire table, blocks all reads & writes
ALTER TABLE users ADD COLUMN token UUID DEFAULT gen_random_uuid();

-- DANGEROUS: Takes ShareLock, blocks all writes (INSERT/UPDATE/DELETE) while building
CREATE INDEX idx_users_email ON users(email);

-- DANGEROUS: Scans entire table under lock to verify referential integrity
ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);
```

When these run under active production traffic:
1. The migration requests an `AccessExclusiveLock`.
2. Any active `SELECT` query prevents the lock from being granted.
3. The migration waits in the queue.
4. **All subsequent queries get queued behind the migration.**
5. Connection pool saturates in seconds $\rightarrow$ **Platform Outage**.

---

## 🛡️ The Solution: SafeMigrate

**SafeMigrate** statically parses your migration SQL files in CI/CD pull requests before deployment:
- **Zero Database Infrastructure Required**: Pure static AST analysis of your SQL migration scripts.
- **Accurate Lock Classification**: Flags `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` locking hazards.
- **Automated Safe DDL Rewriting**: Transforms blocking migrations into safe zero-downtime SQL with `safemigrate fix`.
- **Copy-Paste Remediations**: Emits safe, zero-downtime multi-step SQL migration recipes directly into PR annotations.

🌐 **Try the Live Simulator**: Test PostgreSQL & MySQL migration scripts directly in your browser with zero install at **[https://redintdev.github.io/drillops/safemigrate/](https://redintdev.github.io/drillops/safemigrate/)**.

---

## 🚀 Quickstart

### 1. Installation
```bash
# Turnkey 1-command installer
curl -sSL https://raw.githubusercontent.com/redintDev/safemigrate/main/install.sh | bash

# Or via pip
pip install -e /workspace/projects/safemigrate
```

### 2. View Safety Rule Catalog
```bash
# Inspect all 11 built-in safety rules in formatted table
safemigrate rules

# Filter by dialect
safemigrate rules --dialect postgresql
safemigrate rules --dialect mysql

# Export rule schema to JSON
safemigrate rules --format json
```

### 3. Lint a Migration File
```bash
safemigrate lint migrations/004_add_user_index.sql

# Test against built-in turnkey migration examples
safemigrate lint examples/migrations/001_unsafe_migrations.sql
safemigrate lint examples/migrations/001_safe_migrations.sql
```

### 4. Automatically Rewrite Dangerous Migrations (Auto-Fixer)
```bash
# Preview safe zero-downtime rewrite to stdout
safemigrate fix migrations/004_unsafe_migration.sql

# Show unified diff without modifying files
safemigrate fix migrations/ --diff

# CI/CD check mode (fails if migrations require safe remediation)
safemigrate fix migrations/ --check

# Rewrite all migrations in-place across directory
safemigrate fix migrations/ -i

# Write safe migration to new file
safemigrate fix migrations/004_unsafe_migration.sql -o migrations/004_safe.sql
```

### 5. Scan Entire Migrations Directory
```bash
safemigrate check ./migrations/
```

### 5. Turnkey GitHub Action (.github/workflows/safemigrate.yml)
```yaml
name: SafeMigrate PR Check
on: [pull_request]
jobs:
  lint-migrations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: redintDev/safemigrate@v0.1
        with:
          path: "migrations"
          dialect: "postgresql"
          publish-summary: "true"
          suggest-fixes: "true"
```

### 6. Git Pre-Commit Hook (.pre-commit-config.yaml)
```yaml
repos:
  - repo: https://github.com/redintDev/safemigrate
    rev: v0.1.0
    hooks:
      # Option 1: Automatically rewrite staged migrations in-place on git commit
      - id: safemigrate-fix

      # Option 2: Dry-run check (fails commit if migrations require safe remediation)
      # - id: safemigrate-check

      # Option 3: Lint-only with severity reporting
      # - id: safemigrate
```

---

## 📋 Rule Taxonomy

### PostgreSQL Rules
| Rule ID | Severity | Hazard Description |
| :--- | :---: | :--- |
| **`SM-01`** | `CRITICAL` | `ADD COLUMN ... DEFAULT <volatile>` forces full table rewrite under `AccessExclusiveLock` |
| **`SM-02`** | `HIGH` | `CREATE INDEX` without `CONCURRENTLY` blocks all concurrent writes |
| **`SM-03`** | `HIGH` | `ADD FOREIGN KEY` without `NOT VALID` locks table during full verification scan |
| **`SM-04`** | `CRITICAL` | `ALTER COLUMN TYPE` rewrites table holding `AccessExclusiveLock` |
| **`SM-05`** | `MEDIUM` | `DROP COLUMN` without lock timeout risks queue starvation |
| **`SM-06`** | `LOW` | Missing `SET lock_timeout = '...'` in DDL migration file |

### MySQL & MariaDB Rules
| Rule ID | Severity | Hazard Description |
| :--- | :---: | :--- |
| **`SM-MY-01`** | `HIGH` | `ALTER TABLE` without `ALGORITHM=INSTANT/INPLACE` risks falling back to `ALGORITHM=COPY` |
| **`SM-MY-02`** | `MEDIUM` | DDL lacking explicit `LOCK=NONE` risks acquiring exclusive or shared table locks |
| **`SM-MY-03`** | `HIGH` | Adding foreign key requires `LOCK=SHARED`, blocking writes on parent and child tables |
| **`SM-MY-04`** | `CRITICAL` | `MODIFY/CHANGE COLUMN` type changes force full table rebuilds |
| **`SM-MY-05`** | `LOW` | Missing `SET SESSION lock_wait_timeout` risks 1-year default wait time on metadata locks |

---

## 🤝 Synergistic Ecosystem: The Database Reliability Suite
- **SafeMigrate**: Pre-deployment migration lock & zero-downtime linter in CI/CD.
- **DrillOps**: Post-deployment automated disaster recovery verifier & SOC 2 CC9.1 auditor dossier generator.
