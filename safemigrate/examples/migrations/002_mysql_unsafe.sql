-- SafeMigrate Example: Unsafe Migration Anti-Patterns (MySQL / MariaDB)
-- Run: safemigrate lint 002_mysql_unsafe.sql --dialect mysql

-- Hazard 1: Missing lock_wait_timeout (MySQL default is 1 year)
-- Hazard 2: ALTER TABLE without explicit online ALGORITHM and LOCK clauses
ALTER TABLE orders ADD COLUMN order_notes TEXT;

-- Hazard 3: Adding foreign key in MySQL (takes write locks on parent and child tables)
ALTER TABLE payments ADD CONSTRAINT fk_payments_order FOREIGN KEY (order_id) REFERENCES orders (id);
