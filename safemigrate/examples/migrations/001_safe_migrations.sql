-- SafeMigrate Example: Zero-Downtime Safe Migration Patterns (PostgreSQL)
-- This file demonstrates the production-safe, non-blocking zero-downtime equivalents.
-- Run: safemigrate lint 001_safe_migrations.sql

-- Safe Practice 1: Always set a short fail-safe lock_timeout
SET lock_timeout = '2s';

-- Safe Pattern 2: Safe column addition (instant metadata-only lock)
ALTER TABLE users ADD COLUMN api_token UUID;
ALTER TABLE users ALTER COLUMN api_token SET DEFAULT gen_random_uuid();
-- (Note: backfill existing rows in non-blocking batches in background)

-- Safe Pattern 3: Create index concurrently without write blocking
CREATE INDEX CONCURRENTLY idx_users_created_at ON users (created_at);

-- Safe Pattern 4: Add foreign key with NOT VALID (instant lock), then validate asynchronously
ALTER TABLE orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users (id) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT fk_orders_user;
