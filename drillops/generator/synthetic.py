"""Synthetic test data and backup generator for DrillOps validation."""

import datetime
import gzip
import hashlib
import os
import random
import sqlite3
from typing import Dict, List, Optional, Tuple


class SyntheticDataGenerator:
    """Generates realistic relational database test backups with optional corruption modes."""

    ORGANIZATION_NAMES = [
        "Acme Corp", "Globex Corporation", "Soylent Industries", "Initech", "Umbrella Corp",
        "Hooli Inc", "Pied Piper", "Massive Dynamic", "Stark Enterprises", "Wayne Enterprises",
        "Cyberdyne Systems", "Tyrell Corporation", "Weyland-Yutani", "Oscorp Industries"
    ]

    FIRST_NAMES = ["Alice", "Bob", "Charlie", "Diana", "Evan", "Fiona", "George", "Hannah", "Ian", "Julia", "Kevin", "Laura", "Marcus", "Nora"]
    LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Wilson", "Taylor", "Anderson", "Thomas", "Jackson"]
    PLANS = ["starter", "pro", "enterprise", "custom"]
    ROLES = ["admin", "member", "viewer", "billing_admin"]
    TX_STATUSES = ["settled", "pending", "refunded"]
    EVENT_TYPES = ["user.login", "user.password_reset", "billing.charge.succeeded", "api_key.created", "settings.updated"]

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def _generate_dataset(self, num_users: int = 100) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
        """Generates synthetic relational records across organizations, users, transactions, and audit logs."""
        num_orgs = max(2, num_users // 10)
        orgs = []
        for i in range(1, num_orgs + 1):
            name = self.rng.choice(self.ORGANIZATION_NAMES) + f" {i}"
            slug = name.lower().replace(" ", "-")
            plan = self.rng.choice(self.PLANS)
            orgs.append({
                "id": i,
                "name": name,
                "slug": slug,
                "plan": plan,
                "created_at": "2026-01-01 00:00:00",
            })

        users = []
        for i in range(1, num_users + 1):
            first = self.rng.choice(self.FIRST_NAMES)
            last = self.rng.choice(self.LAST_NAMES)
            org_id = self.rng.randint(1, num_orgs)
            email = f"{first.lower()}.{last.lower()}{i}@example.com"
            users.append({
                "id": i,
                "org_id": org_id,
                "email": email,
                "full_name": f"{first} {last}",
                "role": self.rng.choice(self.ROLES),
                "is_active": 1,
                "created_at": "2026-02-01 10:00:00",
            })

        transactions = []
        num_tx = num_users * 3
        for i in range(1, num_tx + 1):
            user = self.rng.choice(users)
            transactions.append({
                "id": i,
                "org_id": user["org_id"],
                "user_id": user["id"],
                "amount_cents": self.rng.randint(500, 250000),
                "currency": "USD",
                "status": self.rng.choice(self.TX_STATUSES),
                "created_at": "2026-03-01 12:00:00",
            })

        audit_logs = []
        num_logs = num_users * 2
        for i in range(1, num_logs + 1):
            user = self.rng.choice(users)
            audit_logs.append({
                "id": i,
                "event_type": self.rng.choice(self.EVENT_TYPES),
                "actor_email": user["email"],
                "payload_json": '{"ip":"192.168.1.1","client":"drillops-agent"}',
                "ip_address": f"10.0.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}",
                "created_at": "2026-03-02 08:30:00",
            })

        return orgs, users, transactions, audit_logs

    def generate_sqlite_file(
        self,
        output_path: str,
        num_records: int = 100,
        corrupt_mode: Optional[str] = None,
    ) -> Dict:
        """Generates a valid (or corrupted) SQLite backup file."""
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if os.path.exists(output_path):
            os.remove(output_path)

        orgs, users, transactions, audit_logs = self._generate_dataset(num_records)

        conn = sqlite3.connect(output_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE organizations (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                plan TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                org_id INTEGER NOT NULL,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

        # If corrupt_mode is drop_table, omit transactions table to test schema drift
        if corrupt_mode != "drop_table":
            cursor.execute("""
                CREATE TABLE transactions (
                    id INTEGER PRIMARY KEY,
                    org_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

        cursor.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

        cursor.executemany(
            "INSERT INTO organizations VALUES (:id, :name, :slug, :plan, :created_at)", orgs
        )
        cursor.executemany(
            "INSERT INTO users VALUES (:id, :org_id, :email, :full_name, :role, :is_active, :created_at)", users
        )
        if corrupt_mode != "drop_table":
            cursor.executemany(
                "INSERT INTO transactions VALUES (:id, :org_id, :user_id, :amount_cents, :currency, :status, :created_at)", transactions
            )
        cursor.executemany(
            "INSERT INTO audit_logs VALUES (:id, :event_type, :actor_email, :payload_json, :ip_address, :created_at)", audit_logs
        )

        conn.commit()
        conn.close()

        # Apply file-level corruption if requested
        if corrupt_mode == "truncate":
            size = os.path.getsize(output_path)
            with open(output_path, "r+b") as f:
                f.truncate(size // 2)
        elif corrupt_mode == "header_garbage":
            with open(output_path, "r+b") as f:
                f.seek(0)
                f.write(b"CORRUPT_HEADER_NOT_A_SQLITE_FILE_MAGIC_BYTES_DEADBEEF_NULL\x00\x00\x00\x00")

        with open(output_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()

        return {
            "output_path": output_path,
            "engine": "sqlite",
            "file_size": os.path.getsize(output_path),
            "sha256": digest,
            "corrupt_mode": corrupt_mode or "none",
            "tables": ["organizations", "users", "audit_logs"] + ([] if corrupt_mode == "drop_table" else ["transactions"]),
            "record_counts": {
                "organizations": len(orgs),
                "users": len(users),
                "transactions": 0 if corrupt_mode == "drop_table" else len(transactions),
                "audit_logs": len(audit_logs),
            },
        }

    def generate_postgres_sql(
        self,
        output_path: str,
        num_records: int = 100,
        compress_gzip: bool = False,
        corrupt_mode: Optional[str] = None,
    ) -> Dict:
        """Generates a valid (or corrupted) PostgreSQL plain SQL backup dump."""
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        orgs, users, transactions, audit_logs = self._generate_dataset(num_records)

        lines = [
            "-- DrillOps Synthetic PostgreSQL Backup Dump",
            "-- Generated for disaster recovery drill testing",
            "SET statement_timeout = 0;",
            "SET client_encoding = 'UTF8';",
            "",
            "CREATE TABLE IF NOT EXISTS organizations (",
            "    id SERIAL PRIMARY KEY,",
            "    name VARCHAR(255) NOT NULL,",
            "    slug VARCHAR(255) NOT NULL,",
            "    plan VARCHAR(64) NOT NULL,",
            "    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL",
            ");",
            "",
            "CREATE TABLE IF NOT EXISTS users (",
            "    id SERIAL PRIMARY KEY,",
            "    org_id INTEGER NOT NULL REFERENCES organizations(id),",
            "    email VARCHAR(255) NOT NULL UNIQUE,",
            "    full_name VARCHAR(255) NOT NULL,",
            "    role VARCHAR(64) NOT NULL,",
            "    is_active BOOLEAN NOT NULL,",
            "    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL",
            ");",
            "",
        ]

        if corrupt_mode != "drop_table":
            lines.extend([
                "CREATE TABLE IF NOT EXISTS transactions (",
                "    id SERIAL PRIMARY KEY,",
                "    org_id INTEGER NOT NULL,",
                "    user_id INTEGER NOT NULL REFERENCES users(id),",
                "    amount_cents INTEGER NOT NULL,",
                "    currency VARCHAR(8) NOT NULL,",
                "    status VARCHAR(32) NOT NULL,",
                "    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL",
                ");",
                "",
            ])

        lines.extend([
            "CREATE TABLE IF NOT EXISTS audit_logs (",
            "    id SERIAL PRIMARY KEY,",
            "    event_type VARCHAR(128) NOT NULL,",
            "    actor_email VARCHAR(255) NOT NULL,",
            "    payload_json TEXT NOT NULL,",
            "    ip_address VARCHAR(45) NOT NULL,",
            "    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL",
            ");",
            "",
        ])

        # Data inserts
        for o in orgs:
            lines.append(f"INSERT INTO organizations (id, name, slug, plan, created_at) VALUES ({o['id']}, '{o['name']}', '{o['slug']}', '{o['plan']}', '{o['created_at']}');")

        for u in users:
            lines.append(f"INSERT INTO users (id, org_id, email, full_name, role, is_active, created_at) VALUES ({u['id']}, {u['org_id']}, '{u['email']}', '{u['full_name']}', '{u['role']}', TRUE, '{u['created_at']}');")

        if corrupt_mode != "drop_table":
            for t in transactions:
                lines.append(f"INSERT INTO transactions (id, org_id, user_id, amount_cents, currency, status, created_at) VALUES ({t['id']}, {t['org_id']}, {t['user_id']}, {t['amount_cents']}, '{t['currency']}', '{t['status']}', '{t['created_at']}');")

        if corrupt_mode == "syntax_error":
            lines.append("INCORRECT_SQL_COMMAND_SYNTAX_ERROR_CRASH_TEST;")

        for a in audit_logs:
            lines.append(f"INSERT INTO audit_logs (id, event_type, actor_email, payload_json, ip_address, created_at) VALUES ({a['id']}, '{a['event_type']}', '{a['actor_email']}', '{a['payload_json']}', '{a['ip_address']}', '{a['created_at']}');")

        raw_sql = "\n".join(lines) + "\n"

        if corrupt_mode == "truncate":
            raw_sql = raw_sql[:len(raw_sql) // 2]
        elif corrupt_mode == "header_garbage":
            raw_sql = "BROKEN_HEADER_CORRUPTED_DUMP_STREAM\n" + raw_sql[100:]

        content_bytes = raw_sql.encode("utf-8")

        if compress_gzip:
            if not output_path.endswith(".gz"):
                output_path += ".gz"
            with gzip.open(output_path, "wb") as f:
                f.write(content_bytes)
        else:
            with open(output_path, "wb") as f:
                f.write(content_bytes)

        with open(output_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()

        return {
            "output_path": output_path,
            "engine": "postgres",
            "file_size": os.path.getsize(output_path),
            "sha256": digest,
            "corrupt_mode": corrupt_mode or "none",
            "compressed_gzip": compress_gzip,
            "tables": ["organizations", "users", "audit_logs"] + ([] if corrupt_mode == "drop_table" else ["transactions"]),
            "record_counts": {
                "organizations": len(orgs),
                "users": len(users),
                "transactions": 0 if corrupt_mode == "drop_table" else len(transactions),
                "audit_logs": len(audit_logs),
            },
        }

    def generate_mysql_sql(
        self,
        output_path: str,
        num_records: int = 100,
        compress_gzip: bool = False,
        corrupt_mode: Optional[str] = None,
    ) -> Dict:
        """Generates a valid (or corrupted) MySQL / MariaDB SQL backup dump."""
        output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        orgs, users, transactions, audit_logs = self._generate_dataset(num_records)

        lines = [
            "-- DrillOps Synthetic MySQL / MariaDB Backup Dump",
            "-- Generated for disaster recovery drill testing",
            "SET foreign_key_checks = 0;",
            "SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';",
            "",
            "CREATE TABLE IF NOT EXISTS `organizations` (",
            "    `id` INT AUTO_INCREMENT PRIMARY KEY,",
            "    `name` VARCHAR(255) NOT NULL,",
            "    `slug` VARCHAR(255) NOT NULL,",
            "    `plan` VARCHAR(64) NOT NULL,",
            "    `created_at` DATETIME NOT NULL",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "",
            "CREATE TABLE IF NOT EXISTS `users` (",
            "    `id` INT AUTO_INCREMENT PRIMARY KEY,",
            "    `org_id` INT NOT NULL,",
            "    `email` VARCHAR(255) NOT NULL UNIQUE,",
            "    `full_name` VARCHAR(255) NOT NULL,",
            "    `role` VARCHAR(64) NOT NULL,",
            "    `is_active` TINYINT(1) NOT NULL,",
            "    `created_at` DATETIME NOT NULL",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "",
        ]

        if corrupt_mode != "drop_table":
            lines.extend([
                "CREATE TABLE IF NOT EXISTS `transactions` (",
                "    `id` INT AUTO_INCREMENT PRIMARY KEY,",
                "    `org_id` INT NOT NULL,",
                "    `user_id` INT NOT NULL,",
                "    `amount_cents` INT NOT NULL,",
                "    `currency` VARCHAR(8) NOT NULL,",
                "    `status` VARCHAR(32) NOT NULL,",
                "    `created_at` DATETIME NOT NULL",
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                "",
            ])

        lines.extend([
            "CREATE TABLE IF NOT EXISTS `audit_logs` (",
            "    `id` INT AUTO_INCREMENT PRIMARY KEY,",
            "    `event_type` VARCHAR(64) NOT NULL,",
            "    `actor_email` VARCHAR(255) NOT NULL,",
            "    `payload_json` TEXT NOT NULL,",
            "    `ip_address` VARCHAR(45) NOT NULL,",
            "    `created_at` DATETIME NOT NULL",
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
            "",
        ])

        if corrupt_mode == "syntax_error":
            lines.append("THIS IS NOT VALID MYSQL SQL SYNTAX MALFORMED QUERY !!!;;;")

        for o in orgs:
            safe_name = o["name"].replace("'", "''")
            lines.append(
                f"INSERT INTO `organizations` (`id`, `name`, `slug`, `plan`, `created_at`) "
                f"VALUES ({o['id']}, '{safe_name}', '{o['slug']}', '{o['plan']}', '{o['created_at']}');"
            )
        for u in users:
            safe_name = u["full_name"].replace("'", "''")
            lines.append(
                f"INSERT INTO `users` (`id`, `org_id`, `email`, `full_name`, `role`, `is_active`, `created_at`) "
                f"VALUES ({u['id']}, {u['org_id']}, '{u['email']}', '{safe_name}', '{u['role']}', {u['is_active']}, '{u['created_at']}');"
            )
        if corrupt_mode != "drop_table":
            for t in transactions:
                lines.append(
                    f"INSERT INTO `transactions` (`id`, `org_id`, `user_id`, `amount_cents`, `currency`, `status`, `created_at`) "
                    f"VALUES ({t['id']}, {t['org_id']}, {t['user_id']}, {t['amount_cents']}, '{t['currency']}', '{t['status']}', '{t['created_at']}');"
                )
        for a in audit_logs:
            safe_payload = a["payload_json"].replace("'", "''")
            lines.append(
                f"INSERT INTO `audit_logs` (`id`, `event_type`, `actor_email`, `payload_json`, `ip_address`, `created_at`) "
                f"VALUES ({a['id']}, '{a['event_type']}', '{a['actor_email']}', '{safe_payload}', '{a['ip_address']}', '{a['created_at']}');"
            )

        lines.append("SET foreign_key_checks = 1;")
        raw_sql = "\n".join(lines) + "\n"

        if corrupt_mode == "truncate":
            raw_sql = raw_sql[:len(raw_sql) // 2]
        elif corrupt_mode == "header_garbage":
            raw_sql = "BROKEN_HEADER_CORRUPTED_MYSQL_STREAM\n" + raw_sql[100:]

        content_bytes = raw_sql.encode("utf-8")

        if compress_gzip:
            if not output_path.endswith(".gz"):
                output_path += ".gz"
            with gzip.open(output_path, "wb") as f:
                f.write(content_bytes)
        else:
            with open(output_path, "wb") as f:
                f.write(content_bytes)

        with open(output_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()

        return {
            "output_path": output_path,
            "engine": "mysql",
            "file_size": os.path.getsize(output_path),
            "sha256": digest,
            "corrupt_mode": corrupt_mode or "none",
            "compressed_gzip": compress_gzip,
            "tables": ["organizations", "users", "audit_logs"] + ([] if corrupt_mode == "drop_table" else ["transactions"]),
            "record_counts": {
                "organizations": len(orgs),
                "users": len(users),
                "transactions": 0 if corrupt_mode == "drop_table" else len(transactions),
                "audit_logs": len(audit_logs),
            },
        }

