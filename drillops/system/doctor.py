"""System readiness diagnostics and pre-flight inspector for DrillOps."""

from dataclasses import asdict, dataclass
import os
import shutil
import sqlite3
import subprocess
import sys
from typing import Any, Dict, List, Optional

from drillops.licensing.validator import LicenseValidator


@dataclass
class DiagnosticCheck:
    category: str
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    message: str
    details: Optional[str] = None


class SystemDoctor:
    """Runs pre-flight diagnostics to inspect database engines, tools, disk, and permissions."""

    def __init__(self, cert_dir: str = "./certificates", min_disk_gb: float = 2.0):
        self.cert_dir = cert_dir
        self.min_disk_gb = min_disk_gb

    def run_diagnostics(self) -> List[DiagnosticCheck]:
        checks: List[DiagnosticCheck] = []

        # 1. Python environment
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info >= (3, 9):
            checks.append(
                DiagnosticCheck(
                    category="Environment",
                    name="Python Version",
                    status="PASS",
                    message=f"Python {py_ver} supported",
                    details=f"Executable: {sys.executable}",
                )
            )
        else:
            checks.append(
                DiagnosticCheck(
                    category="Environment",
                    name="Python Version",
                    status="FAIL",
                    message=f"Python {py_ver} is unsupported. Python 3.9+ required.",
                )
            )

        # 2. SQLite3 engine
        try:
            sqlite_ver = sqlite3.sqlite_version
            checks.append(
                DiagnosticCheck(
                    category="Database",
                    name="SQLite Engine",
                    status="PASS",
                    message=f"SQLite {sqlite_ver} operational",
                )
            )
        except Exception as e:
            checks.append(
                DiagnosticCheck(
                    category="Database",
                    name="SQLite Engine",
                    status="FAIL",
                    message=f"SQLite error: {e}",
                )
            )

        # 3. PostgreSQL client binaries
        pg_restore_bin = shutil.which("pg_restore")
        psql_bin = shutil.which("psql")
        if pg_restore_bin and psql_bin:
            try:
                out = subprocess.check_output([pg_restore_bin, "--version"], text=True).strip()
                checks.append(
                    DiagnosticCheck(
                        category="Database",
                        name="PostgreSQL Binaries",
                        status="PASS",
                        message=f"Client tools present ({out})",
                        details=f"pg_restore: {pg_restore_bin}",
                    )
                )
            except Exception:
                checks.append(
                    DiagnosticCheck(
                        category="Database",
                        name="PostgreSQL Binaries",
                        status="PASS",
                        message="Binaries located in PATH",
                        details=f"Path: {pg_restore_bin}",
                    )
                )
        elif pg_restore_bin or psql_bin:
            checks.append(
                DiagnosticCheck(
                    category="Database",
                    name="PostgreSQL Binaries",
                    status="WARN",
                    message="Partial PostgreSQL tools found",
                    details=f"pg_restore: {pg_restore_bin}, psql: {psql_bin}",
                )
            )
        else:
            checks.append(
                DiagnosticCheck(
                    category="Database",
                    name="PostgreSQL Binaries",
                    status="WARN",
                    message="PostgreSQL tools not found in PATH",
                    details="Install via: sudo apt install postgresql-client",
                )
            )

        # 4. PostgreSQL local service reachability
        pg_reachable = False
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", 5432))
            sock.close()
            if result == 0:
                pg_reachable = True
        except Exception:
            pass

        if pg_reachable:
            checks.append(
                DiagnosticCheck(
                    category="Database",
                    name="PostgreSQL Service",
                    status="PASS",
                    message="Local PostgreSQL port 5432 reachable",
                )
            )
        else:
            socket_active = False
            if os.path.exists("/var/run/postgresql"):
                try:
                    socket_active = any(
                        f.startswith(".s.PGSQL.5432") for f in os.listdir("/var/run/postgresql")
                    )
                except Exception:
                    pass

            if socket_active:
                checks.append(
                    DiagnosticCheck(
                        category="Database",
                        name="PostgreSQL Service",
                        status="PASS",
                        message="Local PostgreSQL Unix socket active (/var/run/postgresql)",
                    )
                )
            else:
                checks.append(
                    DiagnosticCheck(
                        category="Database",
                        name="PostgreSQL Service",
                        status="WARN",
                        message="Local PostgreSQL service not responding on 5432",
                        details="Acceptable if verifying remote database or SQLite backups",
                    )
                )

        # 5. Output / Certificate directory write permissions
        try:
            test_dir = os.path.abspath(self.cert_dir)
            os.makedirs(test_dir, exist_ok=True)
            test_file = os.path.join(test_dir, ".doctor_write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            checks.append(
                DiagnosticCheck(
                    category="Storage",
                    name="Certificates Directory",
                    status="PASS",
                    message=f"Writable directory: {test_dir}",
                )
            )
        except Exception as e:
            checks.append(
                DiagnosticCheck(
                    category="Storage",
                    name="Certificates Directory",
                    status="FAIL",
                    message=f"Cannot write to {self.cert_dir}: {e}",
                )
            )

        # 6. Disk capacity
        try:
            total, used, free = shutil.disk_usage(os.path.abspath(self.cert_dir))
            free_gb = round(free / (1024**3), 2)
            if free_gb >= self.min_disk_gb:
                checks.append(
                    DiagnosticCheck(
                        category="Storage",
                        name="Disk Capacity",
                        status="PASS",
                        message=f"{free_gb} GB free disk space (threshold >= {self.min_disk_gb} GB)",
                    )
                )
            else:
                checks.append(
                    DiagnosticCheck(
                        category="Storage",
                        name="Disk Capacity",
                        status="WARN",
                        message=f"Low disk space: {free_gb} GB free (< {self.min_disk_gb} GB recommended)",
                    )
                )
        except Exception as e:
            checks.append(
                DiagnosticCheck(
                    category="Storage",
                    name="Disk Capacity",
                    status="WARN",
                    message=f"Unable to check disk usage: {e}",
                )
            )

        # 7. License Verification
        is_valid, lic_info, err = LicenseValidator().validate_key()
        if is_valid and lic_info:
            tier_name = lic_info.tier.value.upper()
            status = "PASS" if tier_name != "COMMUNITY" else "PASS"
            checks.append(
                DiagnosticCheck(
                    category="Licensing",
                    name="Commercial License",
                    status=status,
                    message=f"Tier: {tier_name} (ID: {lic_info.license_id})",
                    details=f"Licensee: {lic_info.customer_name} ({lic_info.customer_email})",
                )
            )
        else:
            checks.append(
                DiagnosticCheck(
                    category="Licensing",
                    name="Commercial License",
                    status="WARN",
                    message=f"Invalid license key: {err}",
                    details="Defaulting to Community tier",
                )
            )

        return checks

    def is_healthy(self, checks: Optional[List[DiagnosticCheck]] = None) -> bool:
        if checks is None:
            checks = self.run_diagnostics()
        return not any(c.status == "FAIL" for c in checks)

    def print_report(self, use_color: bool = True) -> int:
        checks = self.run_diagnostics()
        healthy = self.is_healthy(checks)

        BOLD = "\033[1m" if use_color else ""
        GREEN = "\033[0;32m" if use_color else ""
        YELLOW = "\033[0;33m" if use_color else ""
        RED = "\033[0;31m" if use_color else ""
        CYAN = "\033[0;36m" if use_color else ""
        RESET = "\033[0m" if use_color else ""

        print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
        print(f"{BOLD}  🩺  DRILLOPS SYSTEM DOCTOR & PRE-FLIGHT READINESS INSPECTOR{RESET}")
        print(f"{CYAN}======================================================================{RESET}")

        for cat in ("Environment", "Database", "Storage", "Licensing"):
            cat_checks = [c for c in checks if c.category == cat]
            if not cat_checks:
                continue
            print(f"\n{BOLD}[{cat}]{RESET}")
            for c in cat_checks:
                if c.status == "PASS":
                    badge = f"{GREEN}✔ PASS{RESET}"
                elif c.status == "WARN":
                    badge = f"{YELLOW}⚠ WARN{RESET}"
                else:
                    badge = f"{RED}✖ FAIL{RESET}"

                print(f"  [{badge}] {BOLD}{c.name:<24}{RESET} {c.message}")
                if c.details:
                    print(f"         {c.details}")

        print(f"\n{CYAN}----------------------------------------------------------------------{RESET}")
        if healthy:
            print(f"  {GREEN}{BOLD}Overall Status: HEALTHY — System ready for production restore drills.{RESET}")
            exit_code = 0
        else:
            print(f"  {RED}{BOLD}Overall Status: UNHEALTHY — Correct critical failures above before running drills.{RESET}")
            exit_code = 1
        print(f"{CYAN}======================================================================{RESET}\n")

        return exit_code
