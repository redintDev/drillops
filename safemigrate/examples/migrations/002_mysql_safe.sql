-- SafeMigrate Example: Zero-Downtime Safe Migration Patterns (MySQL / MariaDB)
-- Run: safemigrate lint 002_mysql_safe.sql --dialect mysql

-- Safe Practice 1: Set fail-safe lock_wait_timeout
SET SESSION lock_wait_timeout = 2;

-- Safe Pattern 2: Online DDL with explicit ALGORITHM and LOCK clauses
ALTER TABLE orders ADD COLUMN order_notes TEXT, ALGORITHM=INPLACE, LOCK=NONE;
