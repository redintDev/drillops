# SafeMigrate Migration Examples

This directory contains turnkey SQL migration examples demonstrating common database migration hazards alongside their safe, zero-downtime equivalents for PostgreSQL and MySQL.

## Quickstart

### 1. View All Supported Safety Rules
```bash
safemigrate rules
safemigrate rules --dialect postgresql
safemigrate rules --format json
```

### 2. Linting Dangerous Migrations (PostgreSQL)
Run SafeMigrate against `001_unsafe_migrations.sql`:
```bash
safemigrate lint 001_unsafe_migrations.sql
```
SafeMigrate will detect:
- Missing `lock_timeout` (Connection pool starvation risk)
- Volatile default addition (Full table lock holding `AccessExclusiveLock`)
- Non-concurrent index creation (Write stall)
- Foreign key constraint without `NOT VALID`
- Dangerous column type alteration

### 3. Automated Zero-Downtime Rewriting
Preview the automated zero-downtime fix as a unified diff:
```bash
safemigrate fix 001_unsafe_migrations.sql --diff
```
Or generate safe SQL directly:
```bash
safemigrate fix 001_unsafe_migrations.sql -o my_safe_migration.sql
```

### 4. Verifying Clean Migrations
```bash
safemigrate lint 001_safe_migrations.sql
```
Output:
```
✔ SafeMigrate: 001_safe_migrations.sql PASSED (0 critical, 0 high, 0 medium hazards).
```

### 5. MySQL Online DDL Verification
```bash
safemigrate lint 002_mysql_unsafe.sql --dialect mysql
safemigrate lint 002_mysql_safe.sql --dialect mysql
```
