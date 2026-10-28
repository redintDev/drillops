"""SQLite ephemeral restore engine for DrillOps."""

import os
import sqlite3
import time
from typing import Any, List
from drillops.engines.base import BaseRestoreEngine


class SQLiteRestoreEngine(BaseRestoreEngine):
    """Restores and verifies SQLite database dumps or databases in an isolated environment."""

    def __init__(self, db_path: str = ":memory:"):
        self.target_db_path = db_path
        self.conn: sqlite3.Connection = None
        self._is_file_db = db_path != ":memory:"

    def setup_ephemeral_db(self) -> None:
        if self._is_file_db and os.path.exists(self.target_db_path):
            os.remove(self.target_db_path)
        self.conn = sqlite3.connect(self.target_db_path)
        self.conn.row_factory = sqlite3.Row

    def restore_dump(self, dump_path: str) -> float:
        start_time = time.perf_counter()
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"Dump file does not exist: {dump_path}")

        # Check if dump is raw binary sqlite or SQL text dump
        with open(dump_path, "rb") as f:
            header = f.read(16)

        if header.startswith(b"SQLite format 3"):
            # Binary SQLite database copy
            if self.conn:
                self.conn.close()
            with open(dump_path, "rb") as src, open(self.target_db_path, "wb") as dst:
                dst.write(src.read())
            self.conn = sqlite3.connect(self.target_db_path)
            self.conn.row_factory = sqlite3.Row
        else:
            # SQL script dump
            with open(dump_path, "r", encoding="utf-8", errors="replace") as f:
                script = f.read()
            self.conn.executescript(script)
            self.conn.commit()

        duration = time.perf_counter() - start_time
        return duration

    def execute_query(self, query: str) -> Any:
        if not self.conn:
            raise RuntimeError("Database connection not initialized")
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        if not rows:
            return None
        # If single column single row, return scalar
        if len(rows) == 1 and len(rows[0]) == 1:
            return rows[0][0]
        return [dict(row) for row in rows]

    def list_tables(self) -> List[str]:
        if not self.conn:
            raise RuntimeError("Database connection not initialized")
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        return [row[0] for row in cursor.fetchall()]

    def teardown(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
        if self._is_file_db and os.path.exists(self.target_db_path):
            try:
                os.remove(self.target_db_path)
            except OSError:
                pass
