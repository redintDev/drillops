"""Linux systemd service generator for DrillOps background daemons."""

import os
import shutil
import sys
from typing import Dict, Optional


class SystemdServiceGenerator:
    """Generates standard systemd unit file configurations for DrillOps daemons."""

    @staticmethod
    def generate_service_unit(
        executable: Optional[str] = None,
        working_dir: Optional[str] = None,
        user: Optional[str] = None,
        command_args: str = "watch --dir /var/backups --type postgres",
        env_vars: Optional[Dict[str, str]] = None,
    ) -> str:
        exe_path = executable or shutil.which("drillops") or (sys.executable + " -m drillops.cli")
        work_dir = working_dir or os.getcwd()
        run_user = user or os.environ.get("USER", "root")

        env_lines = []
        if env_vars:
            for k, v in env_vars.items():
                env_lines.append(f'Environment="{k}={v}"')
        env_block = ("\n" + "\n".join(env_lines) + "\n") if env_lines else "\n"

        unit_content = f"""[Unit]
Description=DrillOps Autonomous Disaster Recovery Verification Daemon
Documentation=https://github.com/redintDev/drillops
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User={run_user}
WorkingDirectory={work_dir}{env_block}ExecStart={exe_path} {command_args}
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=drillops

# Sandboxing & Security Hardening
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
"""
        return unit_content
