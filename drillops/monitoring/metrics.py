"""Prometheus Metrics Exporter for DrillOps.

Provides zero-dependency Prometheus exposition format metrics (RFC-standard text format)
for database restore drill status, compliance state, RTO latencies, and assertion counts.
Scraped by Prometheus, Grafana Agent, Datadog Agent, or written to textfile collectors.
"""

from datetime import datetime, timezone
import json
import os
import re
from typing import Any, Dict, List, Optional


class PrometheusMetricsExporter:
    """Aggregates disaster recovery drill certificates and formats Prometheus metrics."""

    def __init__(self, certificates_dir: str = "./certificates"):
        self.certificates_dir = certificates_dir

    def load_certificates(self) -> List[Dict[str, Any]]:
        """Load and parse all JSON drill certificates from the target directory."""
        certs = []
        if not os.path.isdir(self.certificates_dir):
            return certs

        for fname in sorted(os.listdir(self.certificates_dir)):
            if fname.startswith("drill_cert_") and fname.endswith(".json"):
                full_path = os.path.join(self.certificates_dir, fname)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            certs.append(data)
                except Exception:
                    # Defensive parsing; ignore corrupted files gracefully
                    continue
        return certs

    @staticmethod
    def parse_timestamp_to_epoch(ts_str: Optional[str]) -> float:
        """Parse ISO or human timestamp into UTC epoch seconds."""
        if not ts_str:
            return 0.0

        clean = str(ts_str).strip()
        # Handle 'Z' suffix
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        # Handle trailing UTC
        if clean.endswith(" UTC"):
            clean = clean[:-4] + "+00:00"

        try:
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass

        # Fallback common formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(clean, fmt).replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except Exception:
                continue

        return 0.0

    @staticmethod
    def _escape_label_value(val: str) -> str:
        """Escape backslashes, double quotes, and newlines according to Prometheus spec."""
        return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    def collect_metrics(self) -> Dict[str, Any]:
        """Aggregate drill certificates into summary statistics and per-target metrics."""
        certs = self.load_certificates()

        total_drills = len(certs)
        passed_drills = sum(1 for c in certs if c.get("overall_status") == "PASSED")
        failed_drills = total_drills - passed_drills
        pass_ratio = round(passed_drills / total_drills, 4) if total_drills > 0 else 0.0

        rtos: List[float] = []
        total_assertions = 0
        passed_assertions = 0
        failed_assertions = 0
        latest_epoch = 0.0
        latest_rto = 0.0

        targets: Dict[str, Dict[str, Any]] = {}

        for c in certs:
            metrics_dict = c.get("metrics", {})
            rto = float(metrics_dict.get("recovery_time_objective_actual_seconds", 0.0))
            rtos.append(rto)

            total_assertions += int(metrics_dict.get("total_assertions", 0))
            passed_assertions += int(metrics_dict.get("passed_assertions", 0))
            failed_assertions += int(metrics_dict.get("failed_assertions", 0))

            epoch = self.parse_timestamp_to_epoch(c.get("timestamp_utc"))
            if epoch >= latest_epoch:
                latest_epoch = epoch
                latest_rto = rto

            # Target tracking
            target_obj = c.get("target", {})
            target_name = target_obj.get("backup_filename") or "unknown_target"
            db_type = target_obj.get("database_type") or "unknown_db"
            status_num = 1 if c.get("overall_status") == "PASSED" else 0
            size_bytes = int(target_obj.get("backup_size_bytes", 0))

            rpo_obj = c.get("recovery_point_objective", {})
            age_hours = rpo_obj.get("backup_age_hours")
            sla_hours = rpo_obj.get("rpo_sla_hours")
            rpo_status_str = rpo_obj.get("rpo_status", "N/A")
            age_sec = round(float(age_hours) * 3600.0, 2) if age_hours is not None else None
            sla_sec = round(float(sla_hours) * 3600.0, 2) if sla_hours is not None else None
            is_breached = 1 if rpo_status_str == "BREACHED" else 0

            red_obj = c.get("redundancy_and_resilience", {})
            red_status_str = red_obj.get("redundancy_status", "N/A")
            copies_cnt = red_obj.get("copies_count")
            media_cnt = red_obj.get("media_types_count")
            rep_lag_hours = red_obj.get("replication_lag_hours")
            rep_lag_sec = round(float(rep_lag_hours) * 3600.0, 2) if rep_lag_hours is not None else None
            is_red_compliant = 1 if red_status_str == "COMPLIANT" else 0
            integrity_str = red_obj.get("integrity_status", "N/A")
            is_integrity_ok = 1 if integrity_str == "VERIFIED" else 0

            if target_name not in targets:
                targets[target_name] = {
                    "database_type": db_type,
                    "total_drills": 0,
                    "passed_drills": 0,
                    "last_status": status_num,
                    "last_rto": rto,
                    "last_size_bytes": size_bytes,
                    "last_epoch": epoch,
                    "last_backup_age_seconds": age_sec,
                    "rpo_sla_seconds": sla_sec,
                    "rpo_breached": is_breached,
                    "redundancy_copies": copies_cnt,
                    "redundancy_media_types": media_cnt,
                    "redundancy_compliant": is_red_compliant if red_status_str != "N/A" else None,
                    "replication_lag_seconds": rep_lag_sec,
                    "integrity_verified": is_integrity_ok if integrity_str != "N/A" else None,
                }

            t_entry = targets[target_name]
            t_entry["total_drills"] += 1
            if status_num == 1:
                t_entry["passed_drills"] += 1

            if epoch >= t_entry["last_epoch"]:
                t_entry["last_epoch"] = epoch
                t_entry["last_status"] = status_num
                t_entry["last_rto"] = rto
                t_entry["last_size_bytes"] = size_bytes
                t_entry["database_type"] = db_type
                t_entry["last_backup_age_seconds"] = age_sec
                t_entry["rpo_sla_seconds"] = sla_sec
                t_entry["rpo_breached"] = is_breached
                t_entry["redundancy_copies"] = copies_cnt
                t_entry["redundancy_media_types"] = media_cnt
                t_entry["redundancy_compliant"] = is_red_compliant if red_status_str != "N/A" else None
                t_entry["replication_lag_seconds"] = rep_lag_sec
                t_entry["integrity_verified"] = is_integrity_ok if integrity_str != "N/A" else None

        avg_rto = round(sum(rtos) / len(rtos), 3) if rtos else 0.0
        compliance_status = 1 if (total_drills > 0 and passed_drills == total_drills) else 0

        return {
            "total_drills": total_drills,
            "passed_drills": passed_drills,
            "failed_drills": failed_drills,
            "pass_ratio": pass_ratio,
            "average_rto_seconds": avg_rto,
            "last_drill_timestamp_seconds": latest_epoch,
            "last_drill_rto_seconds": latest_rto,
            "compliance_status": compliance_status,
            "total_assertions": total_assertions,
            "passed_assertions": passed_assertions,
            "failed_assertions": failed_assertions,
            "targets": targets,
        }

    def generate_prometheus_exposition(self) -> str:
        """Format metrics strictly according to the Prometheus text exposition format (version 0.0.4)."""
        data = self.collect_metrics()
        lines: List[str] = [
            "# DrillOps Prometheus Metrics Exporter",
            "# Scraped by Prometheus, Grafana Agent, Datadog Agent, or node_exporter textfile collector.",
            "",
            "# HELP drillops_up Indicates if the DrillOps monitoring engine is up and healthy (1 = up)",
            "# TYPE drillops_up gauge",
            "drillops_up 1",
            "",
            "# HELP drillops_drills_total Total number of database restore drills conducted",
            "# TYPE drillops_drills_total counter",
            f"drillops_drills_total {data['total_drills']}",
            "",
            "# HELP drillops_drills_passed_total Total number of passed database restore drills",
            "# TYPE drillops_drills_passed_total counter",
            f"drillops_drills_passed_total {data['passed_drills']}",
            "",
            "# HELP drillops_drills_failed_total Total number of failed database restore drills",
            "# TYPE drillops_drills_failed_total counter",
            f"drillops_drills_failed_total {data['failed_drills']}",
            "",
            "# HELP drillops_drills_pass_ratio Proportion of restore drills passing (0.0 to 1.0)",
            "# TYPE drillops_drills_pass_ratio gauge",
            f"drillops_drills_pass_ratio {data['pass_ratio']}",
            "",
            "# HELP drillops_average_rto_seconds Average recovery time objective (RTO) in seconds",
            "# TYPE drillops_average_rto_seconds gauge",
            f"drillops_average_rto_seconds {data['average_rto_seconds']}",
            "",
            "# HELP drillops_last_drill_timestamp_seconds Unix timestamp of the most recent restore drill in seconds",
            "# TYPE drillops_last_drill_timestamp_seconds gauge",
            f"drillops_last_drill_timestamp_seconds {data['last_drill_timestamp_seconds']}",
            "",
            "# HELP drillops_last_drill_rto_seconds Measured recovery time objective (RTO) in seconds of the latest drill",
            "# TYPE drillops_last_drill_rto_seconds gauge",
            f"drillops_last_drill_rto_seconds {data['last_drill_rto_seconds']}",
            "",
            "# HELP drillops_compliance_status Overall SOC2 CC9.1 compliance state (1 = COMPLIANT, 0 = DEFICIT or NO_DATA)",
            "# TYPE drillops_compliance_status gauge",
            f"drillops_compliance_status {data['compliance_status']}",
            "",
            "# HELP drillops_assertions_total Total database integrity assertions evaluated",
            "# TYPE drillops_assertions_total counter",
            f"drillops_assertions_total {data['total_assertions']}",
            "",
            "# HELP drillops_assertions_passed_total Total database integrity assertions passing",
            "# TYPE drillops_assertions_passed_total counter",
            f"drillops_assertions_passed_total {data['passed_assertions']}",
            "",
            "# HELP drillops_assertions_failed_total Total database integrity assertions failing",
            "# TYPE drillops_assertions_failed_total counter",
            f"drillops_assertions_failed_total {data['failed_assertions']}",
            "",
        ]

        targets = data.get("targets", {})
        if targets:
            lines.extend([
                "# HELP drillops_target_last_drill_status Status of the last drill per target (1 = PASSED, 0 = FAILED)",
                "# TYPE drillops_target_last_drill_status gauge",
            ])
            for target_name, t_info in sorted(targets.items()):
                tgt_esc = self._escape_label_value(target_name)
                db_esc = self._escape_label_value(t_info["database_type"])
                lines.append(f'drillops_target_last_drill_status{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["last_status"]}')
            lines.append("")

            lines.extend([
                "# HELP drillops_target_last_drill_rto_seconds Recovery time objective of the last drill per target in seconds",
                "# TYPE drillops_target_last_drill_rto_seconds gauge",
            ])
            for target_name, t_info in sorted(targets.items()):
                tgt_esc = self._escape_label_value(target_name)
                db_esc = self._escape_label_value(t_info["database_type"])
                lines.append(f'drillops_target_last_drill_rto_seconds{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["last_rto"]}')
            lines.append("")

            lines.extend([
                "# HELP drillops_target_drills_total Total number of drills executed per target",
                "# TYPE drillops_target_drills_total counter",
            ])
            for target_name, t_info in sorted(targets.items()):
                tgt_esc = self._escape_label_value(target_name)
                db_esc = self._escape_label_value(t_info["database_type"])
                lines.append(f'drillops_target_drills_total{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["total_drills"]}')
            lines.append("")

            lines.extend([
                "# HELP drillops_target_last_backup_size_bytes Size of the last verified backup artifact per target in bytes",
                "# TYPE drillops_target_last_backup_size_bytes gauge",
            ])
            for target_name, t_info in sorted(targets.items()):
                tgt_esc = self._escape_label_value(target_name)
                db_esc = self._escape_label_value(t_info["database_type"])
                lines.append(f'drillops_target_last_backup_size_bytes{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["last_size_bytes"]}')
            lines.append("")

            has_age = any(t.get("last_backup_age_seconds") is not None for t in targets.values())
            if has_age:
                lines.extend([
                    "# HELP drillops_target_backup_age_seconds Current age of the target backup artifact in seconds (RPO actual)",
                    "# TYPE drillops_target_backup_age_seconds gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("last_backup_age_seconds") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_backup_age_seconds{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["last_backup_age_seconds"]}')
                lines.append("")

            has_sla = any(t.get("rpo_sla_seconds") is not None for t in targets.values())
            if has_sla:
                lines.extend([
                    "# HELP drillops_target_rpo_sla_seconds Defined Recovery Point Objective SLA threshold in seconds",
                    "# TYPE drillops_target_rpo_sla_seconds gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("rpo_sla_seconds") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_rpo_sla_seconds{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["rpo_sla_seconds"]}')
                lines.append("")

                lines.extend([
                    "# HELP drillops_target_rpo_breached Indicates if target backup age exceeds RPO SLA threshold (1 = BREACHED, 0 = OK)",
                    "# TYPE drillops_target_rpo_breached gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    tgt_esc = self._escape_label_value(target_name)
                    db_esc = self._escape_label_value(t_info["database_type"])
                    lines.append(f'drillops_target_rpo_breached{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info.get("rpo_breached", 0)}')
                lines.append("")

            has_red = any(t.get("redundancy_compliant") is not None for t in targets.values())
            if has_red:
                lines.extend([
                    "# HELP drillops_target_redundancy_compliant Indicates if target satisfies redundancy requirements (1 = COMPLIANT, 0 = NON-COMPLIANT)",
                    "# TYPE drillops_target_redundancy_compliant gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("redundancy_compliant") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_redundancy_compliant{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["redundancy_compliant"]}')
                lines.append("")

                lines.extend([
                    "# HELP drillops_target_redundancy_copies_total Total verified data copies for target including replicas",
                    "# TYPE drillops_target_redundancy_copies_total gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("redundancy_copies") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_redundancy_copies_total{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["redundancy_copies"]}')
                lines.append("")

            has_lag = any(t.get("replication_lag_seconds") is not None for t in targets.values())
            if has_lag:
                lines.extend([
                    "# HELP drillops_target_replication_lag_seconds Observed replication synchronization lag in seconds",
                    "# TYPE drillops_target_replication_lag_seconds gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("replication_lag_seconds") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_replication_lag_seconds{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["replication_lag_seconds"]}')
                lines.append("")

            has_integrity = any(t.get("integrity_verified") is not None for t in targets.values())
            if has_integrity:
                lines.extend([
                    "# HELP drillops_target_integrity_verified Cold-storage archive bit-rot and stream integrity state (1 = VERIFIED, 0 = CORRUPTED)",
                    "# TYPE drillops_target_integrity_verified gauge",
                ])
                for target_name, t_info in sorted(targets.items()):
                    if t_info.get("integrity_verified") is not None:
                        tgt_esc = self._escape_label_value(target_name)
                        db_esc = self._escape_label_value(t_info["database_type"])
                        lines.append(f'drillops_target_integrity_verified{{target="{tgt_esc}",database_type="{db_esc}"}} {t_info["integrity_verified"]}')
                lines.append("")

        return "\n".join(lines).strip() + "\n"

    def write_metrics_file(self, output_path: str) -> None:
        """Write the Prometheus text exposition output to a file for node_exporter or cron."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        text = self.generate_prometheus_exposition()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
