# Zero-Downtime Database Migrations: The Complete Engineering Guide

> **Target Audience**: Backend Engineers, Platform Leads, DBAs, and SREs running production PostgreSQL and MySQL / MariaDB databases.  
> **Tooling**: PostgreSQL 12–17, MySQL 8.0+, MariaDB 10.6+, [SafeMigrate](https://redintdev.github.io/drillops/safemigrate/), and [DrillOps](https://github.com/redintDev/drillops).  
> **Live Simulator**: [https://redintdev.github.io/drillops/safemigrate/](https://redintdev.github.io/drillops/safemigrate/)

---

## 1. The Anatomy of a Table Lock Outage

Every database engineer has experienced or witnessed it: a routine schema migration deployed during low-traffic hours takes down production within seconds.

The misconception is that migrations cause outages because they take hours to run. In reality, **a migration that executes in 50 milliseconds can easily take down a production database**.

### How Lock Queuing Causes Connection Pool Starvation

In relational databases (PostgreSQL and MySQL), locks operate on a **Strict FIFO (First-In, First-Out) queue**:

```
Active Queries (SELECT) ────┐
                            ▼
Incoming DDL Migration ───► [ QUEUE: Waiting for AccessExclusiveLock ] ◄── (Blocked by long SELECT)
                            ▲
Subsequent Reads/Writes ───┴── [ QUEUED BEHIND MIGRATION ] ───► Connection Pool Exhaustion (OUTAGE)
```

1. An unoptimized analytic query or background worker runs a `SELECT` on the `users` table, holding an `AccessShareLock`.
2. A deployment executes:
   ```sql
   ALTER TABLE users ADD COLUMN api_token UUID DEFAULT gen_random_uuid();
   ```
   This DDL requires an `AccessExclusiveLock`, which conflicts with the active `SELECT`.
3. The migration is placed at the front of the lock queue, waiting for the `SELECT` to finish.
4. **All subsequent queries (even simple primary-key lookups like `SELECT * FROM users WHERE id = ?`) conflict with the queued `AccessExclusiveLock`.**
5. Hundreds of application web requests stall waiting in queue.
6. The application connection pool (HikariCP, PgBouncer, SQLAlchemy) reaches `max_connections` in 3 to 10 seconds.
7. Web servers return `HTTP 500 / 504 Gateway Timeout` $\rightarrow$ **Full Site Outage**.

---

## 2. PostgreSQL Lock Modes & Conflict Taxonomy

PostgreSQL uses 8 table lock modes. Schema changes (DDL) frequently take the most restrictive locks:

| Lock Mode | Acquired By | Conflicts With |
| :--- | :--- | :--- |
| **`AccessShareLock`** | `SELECT` | `AccessExclusiveLock` |
| **`RowShareLock`** | `SELECT FOR UPDATE / SHARE` | `ExclusiveLock`, `AccessExclusiveLock` |
| **`RowExclusiveLock`** | `INSERT`, `UPDATE`, `DELETE` | `ShareLock`, `ShareRowExclusiveLock`, `ExclusiveLock`, `AccessExclusiveLock` |
| **`ShareUpdateExclusiveLock`** | `VACUUM` (non-full), `ANALYZE`, `CREATE INDEX CONCURRENTLY`, `VALIDATE CONSTRAINT` | `ShareUpdateExclusiveLock`, `ShareLock`, `ShareRowExclusiveLock`, `ExclusiveLock`, `AccessExclusiveLock` |
| **`ShareLock`** | Standard `CREATE INDEX` | `RowExclusiveLock` (all writes blocked!), `ShareRowExclusiveLock`, `ExclusiveLock`, `AccessExclusiveLock` |
| **`ShareRowExclusiveLock`** | `CREATE TRIGGER` | All locks except `AccessShareLock` |
| **`ExclusiveLock`** | `REFRESH MATERIALIZED VIEW CONCURRENTLY` | All locks except `AccessShareLock` |
| **`AccessExclusiveLock`** | `ALTER TABLE`, `DROP TABLE`, `TRUNCATE`, `VACUUM FULL`, `CLUSTER` | **ALL LOCKS (blocks every read and write!)** |

---

## 3. MySQL & MariaDB Metadata Locking & Online DDL

In MySQL 8.0+ and MariaDB, DDL operations use the **Online DDL** subsystem governed by the `ALGORITHM` and `LOCK` clauses:

### Online DDL Algorithms:
- **`ALGORITHM=INSTANT`**: Modifies dictionary metadata only in ~0.01s. Zero lock waiting, zero disk IO. Available for adding columns at table end in MySQL 8.0.12+ (or anywhere in 8.0.29+).
- **`ALGORITHM=INPLACE`**: Rebuilds or indexes the table in-place without copying data to a temporary table. Permits concurrent reads and writes when paired with `LOCK=NONE`.
- **`ALGORITHM=COPY`**: Legacy engine creating an entire duplicate table, copying rows, and executing a metadata swap under exclusive lock. **Causes production outages on large tables.**

### The MySQL Lock Wait Trap:
By default, MySQL's `lock_wait_timeout` is **31,536,000 seconds (1 full year)**. If an un-parameterized DDL encounters an active query, it stalls for up to 365 days, holding metadata lock tickets that queue all application traffic.

---

## 4. The 6 Universal Zero-Downtime Migration Patterns

### Pattern 1: Non-Blocking Index Creation

#### The Hazard (`SM-02` / `HIGH`):
```sql
-- DANGEROUS: Takes ShareLock, blocking all concurrent INSERT, UPDATE, DELETE
CREATE INDEX idx_orders_customer ON orders(customer_id);
```

#### The Zero-Downtime Fix:
```sql
-- SAFE: Run in autocommit mode outside a transaction block
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_customer ON orders(customer_id);
```
*Note: `CONCURRENTLY` uses two snapshot scans and takes only `ShareUpdateExclusiveLock`, allowing concurrent writes throughout the build.*

---

### Pattern 2: 2-Step Safe Foreign Key Addition

#### The Hazard (`SM-03` / `HIGH`):
```sql
-- DANGEROUS: Takes AccessExclusiveLock and scans entire table to verify existing rows
ALTER TABLE payments ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);
```

#### The Zero-Downtime Fix:
```sql
-- Step 1: Add constraint with NOT VALID (instant metadata-only lock, ~5ms)
ALTER TABLE payments ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;

-- Step 2: Validate existing rows without blocking concurrent reads or writes
ALTER TABLE payments VALIDATE CONSTRAINT fk_user;
```
*`VALIDATE CONSTRAINT` acquires only `ShareUpdateExclusiveLock`, which does not block `SELECT`, `INSERT`, `UPDATE`, or `DELETE`.*

---

### Pattern 3: 3-Step Volatile Column Default Addition

#### The Hazard (`SM-01` / `CRITICAL`):
In PostgreSQL 11+, non-volatile defaults (`DEFAULT 'active'` or `DEFAULT 0`) are metadata-only instant operations. However, **volatile functions** (`gen_random_uuid()`, `clock_timestamp()`, or `random()`) force PostgreSQL to rewrite every tuple in the table under `AccessExclusiveLock`:
```sql
-- DANGEROUS: Rewrites every table row holding AccessExclusiveLock
ALTER TABLE users ADD COLUMN api_token UUID DEFAULT gen_random_uuid();
```

#### The Zero-Downtime Fix:
```sql
-- Step 1: Add column without default (instant metadata-only, ~2ms)
ALTER TABLE users ADD COLUMN api_token UUID;

-- Step 2: Set default for all future inserts (instant metadata-only, ~2ms)
ALTER TABLE users ALTER COLUMN api_token SET DEFAULT gen_random_uuid();

-- Step 3: Backfill historical rows in small batches outside transaction
-- Example batch script:
-- UPDATE users SET api_token = gen_random_uuid() WHERE id IN (SELECT id FROM users WHERE api_token IS NULL LIMIT 5000);
```

---

### Pattern 4: 4-Step Column Type Alteration (Shadow Column Pattern)

#### The Hazard (`SM-04` / `CRITICAL`):
```sql
-- DANGEROUS: Rewrites table data tuples under AccessExclusiveLock
ALTER TABLE users ALTER COLUMN age TYPE BIGINT;
```

#### The Zero-Downtime Fix:
1. **Add new column**: `ALTER TABLE users ADD COLUMN age_new BIGINT;`
2. **Dual-write**: Application writes to both `age` and `age_new` (or database trigger).
3. **Backfill**: Background worker updates historical rows in batches (`UPDATE users SET age_new = age WHERE age_new IS NULL LIMIT 5000;`).
4. **Rename swap**:
   ```sql
   SET lock_timeout = '2s';
   ALTER TABLE users RENAME COLUMN age TO age_old;
   ALTER TABLE users RENAME COLUMN age_new TO age;
   ```

---

### Pattern 5: Safe Column Dropping with Lock Timeout

#### The Hazard (`SM-05` / `MEDIUM`):
Dropping a column requires `AccessExclusiveLock`. While the drop itself is metadata-only, queue starvation will occur if long queries are active.

#### The Zero-Downtime Fix:
Always wrap drops with lock timeouts and optional view abstraction:
```sql
SET lock_timeout = '2s';
ALTER TABLE users DROP COLUMN unused_field;
```

---

### Pattern 6: The Universal Lock Timeout Defense

#### The Rule (`SM-06` / `SM-MY-05`):
**Every DDL script that executes against production must specify a short lock timeout.**

- **PostgreSQL**:
  ```sql
  SET lock_timeout = '2s';
  ```
- **MySQL / MariaDB**:
  ```sql
  SET SESSION lock_wait_timeout = 5;
  ```

If the lock cannot be acquired within 2 seconds, the migration fails fast with an error, rolling back cleanly and allowing application traffic to continue uninterrupted without connection saturation.

---

## 5. Automated Enforcement with SafeMigrate

You do not need to memorize these rules manually. **SafeMigrate** automatically enforces them in CI/CD pull requests and pre-commit hooks:

### 1. Static Linting & Auditing
```bash
safemigrate check ./migrations/
```

### 2. Automated Zero-Downtime Rewriting
```bash
# Preview unified diff
safemigrate fix migrations/ --diff

# Rewrite files in-place
safemigrate fix migrations/ -i
```

### 3. GitHub Action CI/CD Integration
```yaml
name: SafeMigrate
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: redintDev/safemigrate@v0.1
        with:
          path: "migrations"
          suggest-fixes: "true"
```

### 4. Git Pre-Commit Hook
```yaml
repos:
  - repo: https://github.com/redintDev/safemigrate
    rev: v0.1.0
    hooks:
      - id: safemigrate-fix
```

---

## 6. Synergistic Ecosystem: The Database Reliability Suite

Zero-downtime reliability spans before and after deployment:

1. **Pre-Deployment Safety ([SafeMigrate](https://redintdev.github.io/drillops/safemigrate/))**:
   - Statically intercepts dangerous table locks and metadata starvation in pull requests before DDL hits production.
   - 🌐 [Test the Live Migration Lock Simulator](https://redintdev.github.io/drillops/safemigrate/)
2. **Post-Deployment Resilience ([DrillOps](https://github.com/redintDev/drillops))**:
   - Automatically verifies database disaster recovery backups in isolated ephemeral containers.
   - Measures sub-second RTO/RPO SLAs and generates cryptographically signed SOC 2 CC9.1 / ISO 27001 evidence dossiers.
   - 🌐 [DrillOps Automated DR Verification](https://redintdev.github.io/drillops/)
