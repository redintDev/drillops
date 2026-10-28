"""MySQL and MariaDB ephemeral restore engine for DrillOps."""

import os
import subprocess
import time
import uuid
from typing import Any, List, Optional
from drillops.engines.base import BaseRestoreEngine


class MySQLRestoreEngine(BaseRestoreEngine):
    """
    Manages ephemeral MySQL / MariaDB test databases, executes client restores,
    and conducts verification queries.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        admin_db: str = "mysql",
        test_db_prefix: str = "drillops_test_",
    ):
        self.host = host or os.environ.get("DRILLOPS_MYSQL_HOST") or os.environ.get("MYSQL_HOST") or "localhost"
        env_port = os.environ.get("DRILLOPS_MYSQL_PORT") or os.environ.get("MYSQL_PORT")
        self.port = port if port is not None else (int(env_port) if env_port else 3306)
        self.user = user or os.environ.get("DRILLOPS_MYSQL_USER") or os.environ.get("MYSQL_USER") or os.environ.get("USER") or "root"
        self.password = password or os.environ.get("DRILLOPS_MYSQL_PASSWORD") or os.environ.get("MYSQL_PASSWORD") or os.environ.get("MYSQL_PWD")
        self.admin_db = admin_db
        self.temp_db_name = f"{test_db_prefix}{uuid.uuid4().hex[:8]}"
        self._env = os.environ.copy()
        if self.password:
            self._env["MYSQL_PWD"] = self.password

    def _build_base_cmd(self, dbname: Optional[str] = None) -> List[str]:
        cmd = [
            "mysql",
            "-h", self.host,
            "-P", str(self.port),
            "-u", self.user,
        ]
        if dbname:
            cmd.append(dbname)
        return cmd

    def _run_mysql_cmd(self, dbname: Optional[str], sql: str) -> str:
        cmd = self._build_base_cmd(dbname) + ["-B", "-N", "-e", sql]
        res = subprocess.run(cmd, env=self._env, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"MySQL execution failed (exit {res.returncode}): {res.stderr.strip()}")
        return res.stdout.strip()

    def setup_ephemeral_db(self) -> None:
        """Create the temporary isolated database on the server."""
        sql = (
            f"CREATE DATABASE IF NOT EXISTS `{self.temp_db_name}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
        self._run_mysql_cmd(self.admin_db, sql)

    def restore_dump(self, dump_path: str) -> float:
        """
        Executes restore of MySQL/MariaDB SQL script dump into the ephemeral database.
        """
        if not os.path.exists(dump_path):
            raise FileNotFoundError(f"MySQL dump file not found: {dump_path}")

        start_time = time.perf_counter()

        cmd = self._build_base_cmd(self.temp_db_name)

        with open(dump_path, "r", encoding="utf-8", errors="replace") as f_in:
            res = subprocess.run(
                cmd,
                env=self._env,
                stdin=f_in,
                capture_output=True,
                text=True,
            )

        if res.returncode != 0:
            raise RuntimeError(f"MySQL database restore failed (exit {res.returncode}): {res.stderr.strip()}")

        return time.perf_counter() - start_time

    def execute_query(self, query: str) -> Any:
        output = self._run_mysql_cmd(self.temp_db_name, query)
        lines = [l for l in output.splitlines() if l.strip()]
        if not lines:
            return None
        if len(lines) == 1:
            val = lines[0].strip()
            # If tab-delimited row, return columns
            parts = val.split("\t")
            if len(parts) > 1:
                return parts
            if val.isdigit():
                return int(val)
            try:
                return float(val)
            except ValueError:
                return val
        # Multi-row: return list of rows
        parsed_rows = []
        for line in lines:
            parts = line.strip().split("\t")
            parsed_rows.append(parts[0] if len(parts) == 1 else parts)
        return parsed_rows

    def list_tables(self) -> List[str]:
        sql = (
            f"SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema='{self.temp_db_name}' AND table_type='BASE TABLE';"
        )
        out = self._run_mysql_cmd(self.admin_db, sql)
        return [l.strip() for l in out.splitlines() if l.strip()]

    def teardown(self) -> None:
        """Drop the ephemeral test database and release resources."""
        try:
            self._run_mysql_cmd(self.admin_db, f"DROP DATABASE IF EXISTS `{self.temp_db_name}`;")
        except Exception:
            pass
