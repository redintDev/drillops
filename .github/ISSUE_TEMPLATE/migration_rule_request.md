---
name: "SafeMigrate Rule Request / Migration Pattern Analysis"
about: "Propose a new zero-downtime lint rule, report an unhandled unsafe DDL pattern, or request lock analysis for an ORM migration"
title: "[Migration Rule Request]: <DDL / ORM Pattern>"
labels: ["safemigrate", "migration-analysis", "enhancement"]
assignees: []
---

### 🛡️ SafeMigrate Rule Request / Unsafe DDL Analysis

#### 1. Target Database Engine
- [ ] PostgreSQL (14 / 15 / 16 / 17)
- [ ] MySQL (8.0 / 8.4) / MariaDB (10.x / 11.x)
- [ ] Other (e.g. SQLite, CockroachDB)

#### 2. Migration Framework / Tool
- [ ] Raw SQL DDL (`.sql` files)
- [ ] Alembic (Python / SQLAlchemy)
- [ ] Django Migrations (Python)
- [ ] Prisma (Node.js / TypeScript)
- [ ] Flyway / Liquibase (Java)
- [ ] Goose / Golang Migrate (Go)
- [ ] Other: 

#### 3. Unsafe DDL Pattern / SQL Snippet
```sql
-- Paste the SQL statement(s) that cause lock contention or table locks here:
ALTER TABLE ...
```

#### 4. Expected Lock Contention / Production Risk
- **Lock Mode Acquired**: (e.g. `AccessExclusiveLock`, `ShareLock`, MySQL `EXCLUSIVE` metadata lock)
- **Observed / Expected Behavior**: (e.g. locks reads, rewrites whole table, causes connection starvation)
- **Zero-Downtime Workaround / Suggested Pattern**: (e.g. `ADD COLUMN ... DEFAULT NULL`, `CREATE INDEX CONCURRENTLY`, `VALIDATE CONSTRAINT`)

#### 5. Proposed SafeMigrate Lint Rule
- **Rule ID Suggestion**: (e.g. `SM-07`, `SM-MY-06`)
- **Severity**:
  - [ ] CRITICAL (Acquires `AccessExclusiveLock` or rewrites table; blocks all concurrent SELECTs)
  - [ ] WARNING (Acquires `ShareLock`; allows SELECTs but blocks INSERT/UPDATE/DELETE)
  - [ ] INFO (Best-practice suggestion, e.g. missing `lock_timeout`)
- **Automated Fix (`safemigrate fix`)**: Can this be safely rewritten into a multi-step pattern automatically?
