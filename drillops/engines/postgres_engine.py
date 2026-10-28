"""PostgreSQL ephemeral restore engine for DrillOps."""

import os
import subprocess
import time
import uuid
from typing import Any, List, Optional
from drillops.engines.base import BaseRestoreEngine


class PostgresRestoreEngine(BaseRestoreEngine):
    """
    Manages ephemeral PostgreSQL test databases, executes pg_restore / psql,
    and conducts verification queries.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        user: str = "postgres",
        password: Optional[str] = None,
        admin_db: str = "postgres",
        test_db_prefix: str = "drillops_test_",
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.admin_db = admin_db
        self.temp_db_name = f"{test_db_prefix}{uuid.uuid4().hex[:8]}"
        self._env = os.environ.copy()
        self._env["PAGER"] = "cat"
        self._env["PGPAGER"] = "cat"
        if self.password:
            self._env["PGPASSWORD"] = self.password

    def _run_psql_cmd(self, dbname: str, sql: str) -> str:
        cmd = [
            "psql",
            "-h", self.host,
            "-p", str(self.port),
            "-U", self.user,
            "-d", dbname,
            "-X", "-A", "-t",
            "-c", sql,
        ]
        res = subprocess.run(cmd, env=self._env, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"psql execution failed: {res.stderr.strip()}")
        return res.stdout.strip()

    def setup_ephemeral_db(self) -> None:
        """Create the temporary isolated database on the server."""
        self._run_psql_cmd(self.admin_db, f"CREATE DATABASE {self.temp_db_name};")

    def restore_dump(self, dump_path: str) -> float:
        """
        Executes restore using pg_restore (if custom/directory dump)
        or psql (if plain SQL script).
        """
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"PostgreSQL dump file not found: {dump_path}")

        start_time = time.perf_counter()

        with open(dump_path, "rb") as f:
            header = f.read(5)

        is_custom_dump = header.startswith(b"PGDMP")

        if is_custom_dump:
            cmd = [
                "pg_restore",
                "-h", self.host,
                "-p", str(self.port),
                "-U", self.user,
                "-d", self.temp_db_name,
                "--no-owner",
                "--no-privileges",
                dump_path,
            ]
        else:
            cmd = [
                "psql",
                "-h", self.host,
                "-p", str(self.port),
                "-U", self.user,
                "-d", self.temp_db_name,
                "-X",
                "-f", dump_path,
            ]

        res = subprocess.run(cmd, env=self._env, capture_output=True, text=True)
        # Note: pg_restore returns exit code 1 on non-fatal warnings, so check output
        if res.returncode not in (0, 1):
            raise RuntimeError(f"Database restore failed: {res.stderr.strip()}")

        return time.perf_counter() - start_time

    def execute_query(self, query: str) -> Any:
        output = self._run_psql_cmd(self.temp_db_name, query)
        lines = [l for l in output.splitlines() if l.strip()]
        if not lines:
            return None
        if len(lines) == 1:
            val = lines[0].strip()
            if val.isdigit():
                return int(val)
            try:
                return float(val)
            except ValueError:
                return val
        return lines

    def list_tables(self) -> List[str]:
        sql = "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';"
        out = self._run_psql_cmd(self.temp_db_name, sql)
        return [l.strip() for l in out.splitlines() if l.strip()]

    def teardown(self) -> None:
        """Terminate connections and drop the ephemeral test database."""
        try:
            # Terminate active backend connections to the temp db
            term_sql = (
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{self.temp_db_name}' AND pid <> pg_backend_pid();"
            )
            self._run_psql_cmd(self.admin_db, term_sql)
            self._run_psql_cmd(self.admin_db, f"DROP DATABASE IF EXISTS {self.temp_db_name};")
        except Exception:
            pass
