-- SafeMigrate Example: Unsafe Migration Anti-Patterns (PostgreSQL)
-- This file contains common dangerous DDL patterns that cause table lockups and downtime.
-- Run: safemigrate lint 001_unsafe_migrations.sql

-- Hazard 1: Missing lock_timeout (can stall connection pool behind slow queries)
-- Hazard 2: Column addition with volatile default function (AccessExclusiveLock + table rewrite)
ALTER TABLE users ADD COLUMN api_token UUID DEFAULT gen_random_uuid();

-- Hazard 3: Creating index without CONCURRENTLY (ShareLock blocks INSERT/UPDATE/DELETE)
CREATE INDEX idx_users_created_at ON users (created_at);

-- Hazard 4: Adding foreign key constraint without NOT VALID (scans millions of rows under lock)
ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users (id);

-- Hazard 5: Changing column data type (full table rewrite and metadata lock)
ALTER TABLE audit_logs ALTER COLUMN ip_address TYPE VARCHAR(45);

-- Hazard 6: Dropping column without prior deprecation/lock timeout
ALTER TABLE customers DROP COLUMN legacy_notes;
