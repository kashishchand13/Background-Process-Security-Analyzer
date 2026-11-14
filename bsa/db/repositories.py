import json
import os
import platform
from datetime import datetime
from typing import Iterable

import oracledb

from bsa.core.models import ProcessSnapshot, ReputationRule
from bsa.core.path_utils import path_is_within


class SystemRepository:
    def get_or_create(self, connection) -> int:
        hostname = platform.node() or "unknown-host"
        os_name = platform.system() or "Windows"
        os_version = platform.version() or platform.release()
        cursor = connection.cursor()
        cursor.execute("SELECT system_id FROM systems WHERE hostname=:1", (hostname,))
        row = cursor.fetchone()
        now = datetime.now()
        if row:
            system_id = int(row[0])
            cursor.execute(
                "UPDATE systems SET os_name=:1, os_version=:2, last_seen=:3 WHERE system_id=:4",
                (os_name, os_version, now, system_id),
            )
            cursor.close()
            return system_id
        system_id = cursor.insert_returning_id(
            "INSERT INTO systems (hostname, os_name, os_version, last_seen) VALUES (:1,:2,:3,:4)",
            (hostname, os_name, os_version, now),
            "system_id",
        )
        cursor.close()
        return system_id


class SessionRepository:
    def start(self, connection, system_id: int) -> int:
        cursor = connection.cursor()
        session_id = cursor.insert_returning_id(
            "INSERT INTO scan_sessions (system_id, session_status) VALUES (:1, 'RUNNING')",
            (system_id,),
            "session_id",
        )
        cursor.close()
        return session_id

    def update_count(self, connection, session_id: int, count: int) -> None:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE scan_sessions SET processes_scanned=:1 WHERE session_id=:2",
            (count, session_id),
        )
        cursor.close()

    def end_with_connection(self, connection, session_id: int, status: str = "STOPPED") -> None:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE scan_sessions SET session_status=:1, ended_at=:2 WHERE session_id=:3",
            (status, datetime.now(), session_id),
        )
        cursor.close()


class ReputationRuleRepository:
    def seed_builtin_rules(self, connection) -> None:
        windows_dir = os.environ.get("WINDIR", r"C:\Windows")
        system32 = os.path.join(windows_dir, "System32")
        syswow64 = os.path.join(windows_dir, "SysWOW64")
        builtins = [
            ("svchost.exe", system32, "TRUSTED", "Windows service host; path-based default rule"),
            ("svchost.exe", syswow64, "TRUSTED", "Windows service host; supported 32-bit path-based default rule"),
            ("lsass.exe", system32, "TRUSTED", "Windows Local Security Authority; path-based default rule"),
            ("services.exe", system32, "TRUSTED", "Windows Service Control Manager; path-based default rule"),
            ("winlogon.exe", system32, "TRUSTED", "Windows logon process; path-based default rule"),
            ("csrss.exe", system32, "TRUSTED", "Windows client/server runtime; path-based default rule"),
            ("wininit.exe", system32, "TRUSTED", "Windows initialization process; path-based default rule"),
            ("smss.exe", system32, "TRUSTED", "Windows Session Manager; path-based default rule"),
            ("spoolsv.exe", system32, "TRUSTED", "Windows print spooler; path-based default rule"),
            ("dwm.exe", system32, "TRUSTED", "Windows Desktop Window Manager; path-based default rule"),
            ("taskhostw.exe", system32, "TRUSTED", "Windows task host; path-based default rule"),
            ("taskhostw.exe", syswow64, "TRUSTED", "Windows task host; supported 32-bit path-based default rule"),
            ("runtimebroker.exe", system32, "TRUSTED", "Windows Runtime Broker; path-based default rule"),
            ("runtimebroker.exe", syswow64, "TRUSTED", "Windows Runtime Broker; supported 32-bit path-based default rule"),
            ("explorer.exe", windows_dir, "TRUSTED", "Windows shell; path-based default rule"),
        ]
        cursor = connection.cursor()
        for name, path, reputation, reason in builtins:
            cursor.execute(
                "SELECT rule_id FROM reputation_rules WHERE LOWER(process_name)=:1 "
                "AND LOWER(expected_path_prefix)=:2 AND is_enabled='Y' FETCH FIRST 1 ROWS ONLY",
                (name.lower(), path.lower()),
            )
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO reputation_rules "
                    "(process_name, expected_path_prefix, reputation, reason, is_enabled) "
                    "VALUES (:1, :2, :3, :4, 'Y')",
                    (name, path, reputation, reason),
                )
        cursor.close()

    def list_enabled(self, connection) -> list[ReputationRule]:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT rule_id, process_name, expected_path_prefix, sha256_hash, reputation, reason "
            "FROM reputation_rules WHERE is_enabled='Y'"
        )
        rows = cursor.fetchall()
        cursor.close()
        return [ReputationRule(**row) for row in rows]


class ProcessRepository:
    def mark_inactive(self, connection, system_id: int) -> None:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE process_instances SET is_active='N' "
            "WHERE system_id=:1 AND is_active='Y'",
            (system_id,),
        )
        cursor.close()

    def upsert_many(self, connection, system_id: int, snapshots: list[ProcessSnapshot]) -> dict[int, int]:
        if not snapshots:
            return {}
        now = datetime.now()
        values = []
        for p in snapshots:
            created = datetime.fromtimestamp(p.create_time)
            created = created.replace(microsecond=(created.microsecond // 1000) * 1000)
            values.append((
                system_id, p.pid, created, p.process_name[:255], p.executable_path,
                p.parent_pid, p.parent_name, p.username, p.state,
                p.priority_value, p.cpu_percent, p.memory_bytes,
                p.memory_percent, p.thread_count, p.reputation_status,
                p.risk_score, p.analysis_summary[:500], 'Y', now, now,
            ))

        # Oracle MERGE provides an upsert keyed by system + PID + process creation time.
        merge_sql = """
            MERGE INTO process_instances t
            USING (
                SELECT :1 AS system_id,
                       :2 AS pid,
                       CAST(:3 AS TIMESTAMP) AS create_time,
                       CAST(:4 AS VARCHAR2(255)) AS process_name,
                       CAST(:5 AS VARCHAR2(1024)) AS executable_path,
                       CAST(:6 AS NUMBER) AS parent_pid,
                       CAST(:7 AS VARCHAR2(255)) AS parent_name,
                       CAST(:8 AS VARCHAR2(255)) AS username,
                       CAST(:9 AS VARCHAR2(40)) AS process_state,
                       CAST(:10 AS NUMBER) AS priority_value,
                       CAST(:11 AS NUMBER) AS current_cpu_percent,
                       CAST(:12 AS NUMBER) AS current_memory_bytes,
                       CAST(:13 AS NUMBER) AS current_memory_percent,
                       CAST(:14 AS NUMBER) AS thread_count,
                       CAST(:15 AS VARCHAR2(20)) AS reputation_status,
                       CAST(:16 AS NUMBER) AS risk_score,
                       CAST(:17 AS VARCHAR2(500)) AS analysis_summary,
                       CAST(:18 AS CHAR(1)) AS is_active,
                       CAST(:19 AS TIMESTAMP) AS first_seen,
                       CAST(:20 AS TIMESTAMP) AS last_seen
                FROM dual
            ) s
            ON (t.system_id=s.system_id AND t.pid=s.pid AND t.create_time=s.create_time)
            WHEN MATCHED THEN UPDATE SET
                process_name=s.process_name,
                executable_path=s.executable_path,
                parent_pid=s.parent_pid,
                parent_name=s.parent_name,
                username=s.username,
                process_state=s.process_state,
                priority_value=s.priority_value,
                current_cpu_percent=s.current_cpu_percent,
                current_memory_bytes=s.current_memory_bytes,
                current_memory_percent=s.current_memory_percent,
                thread_count=s.thread_count,
                reputation_status=s.reputation_status,
                risk_score=s.risk_score,
                analysis_summary=s.analysis_summary,
                is_active='Y',
                last_seen=s.last_seen
            WHEN NOT MATCHED THEN INSERT
                (system_id,pid,create_time,process_name,executable_path,parent_pid,parent_name,username,
                 process_state,priority_value,current_cpu_percent,current_memory_bytes,current_memory_percent,
                 thread_count,reputation_status,risk_score,analysis_summary,is_active,first_seen,last_seen)
            VALUES
                (s.system_id,s.pid,s.create_time,s.process_name,s.executable_path,s.parent_pid,s.parent_name,s.username,
                 s.process_state,s.priority_value,s.current_cpu_percent,s.current_memory_bytes,s.current_memory_percent,
                 s.thread_count,s.reputation_status,s.risk_score,s.analysis_summary,s.is_active,s.first_seen,s.last_seen)
        """
        cursor = connection.cursor()
        # Explicit bind types prevent None values in early rows from determining array types.
        cursor.setinputsizes(
            oracledb.DB_TYPE_NUMBER, oracledb.DB_TYPE_NUMBER, oracledb.DB_TYPE_TIMESTAMP,
            255, 1024, oracledb.DB_TYPE_NUMBER, 255, 255, 40, oracledb.DB_TYPE_NUMBER,
            oracledb.DB_TYPE_NUMBER, oracledb.DB_TYPE_NUMBER, oracledb.DB_TYPE_NUMBER,
            oracledb.DB_TYPE_NUMBER, 20, oracledb.DB_TYPE_NUMBER, 500, 1,
            oracledb.DB_TYPE_TIMESTAMP, oracledb.DB_TYPE_TIMESTAMP,
        )
        cursor.executemany(merge_sql, values)
        cursor.execute(
            "SELECT process_id, pid FROM process_instances WHERE system_id=:1 AND is_active='Y'",
            (system_id,),
        )
        mapping = {int(row[1]): int(row[0]) for row in cursor.fetchall()}
        cursor.close()
        return mapping

    def update_analysis(self, connection, system_id: int, snapshots: list[ProcessSnapshot]) -> None:
        cursor = connection.cursor()
        cursor.executemany(
            "UPDATE process_instances SET reputation_status=:1, risk_score=:2, analysis_summary=:3 "
            "WHERE system_id=:4 AND pid=:5 AND is_active='Y'",
            [(p.reputation_status, p.risk_score, p.analysis_summary[:500], system_id, p.pid) for p in snapshots],
        )
        cursor.close()

    def find_instance_id(self, connection, system_id: int, pid: int, create_time: float) -> int | None:
        created = datetime.fromtimestamp(create_time)
        created = created.replace(microsecond=(created.microsecond // 1000) * 1000)
        cursor = connection.cursor()
        cursor.execute(
            "SELECT process_id FROM process_instances WHERE system_id=:1 AND pid=:2 AND create_time=:3 FETCH FIRST 1 ROWS ONLY",
            (system_id, pid, created),
        )
        row = cursor.fetchone()
        cursor.close()
        return int(row[0]) if row else None

    def list_active(self, connection, limit: int = 500) -> list[dict]:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT process_id,pid,process_name,executable_path,parent_pid,parent_name,process_state,"
            "priority_value,current_cpu_percent,current_memory_bytes,current_memory_percent,thread_count,"
            "reputation_status,risk_score,analysis_summary,last_seen "
            "FROM process_instances WHERE is_active='Y' ORDER BY risk_score DESC,current_cpu_percent DESC "
            "FETCH FIRST :1 ROWS ONLY", (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


class HistoryRepository:
    def add_event(self, connection, session_id: int, process_id: int, event_type: str,
                  snapshot: ProcessSnapshot, details: str = "") -> None:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO process_history "
            "(session_id,process_id,event_type,pid,process_name,executable_path,event_details) "
            "VALUES (:1,:2,:3,:4,:5,:6,:7)",
            (session_id, process_id, event_type, snapshot.pid, snapshot.process_name,
             snapshot.executable_path, details[:500] or None),
        )
        cursor.close()

    def list_recent(self, connection, limit: int = 100) -> list[dict]:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT h.history_id,h.event_type,h.pid,h.process_name,h.executable_path,"
            "h.event_details,h.occurred_at FROM process_history h "
            "ORDER BY h.occurred_at DESC FETCH FIRST :1 ROWS ONLY", (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        return rows


class MetricsRepository:
    def insert_many(self, connection, session_id: int, process_id_by_pid: dict[int, int],
                    snapshots: Iterable[ProcessSnapshot]) -> None:
        values = []
        for p in snapshots:
            process_id = process_id_by_pid.get(p.pid)
            if process_id is None:
                continue
            values.append((session_id, process_id, p.cpu_percent, p.memory_bytes,
                           p.memory_percent, p.thread_count, p.io_read_bytes, p.io_write_bytes))
        if not values:
            return
        cursor = connection.cursor()
        cursor.setinputsizes(*([oracledb.DB_TYPE_NUMBER] * 8))
        cursor.executemany(
            "INSERT INTO process_metrics "
            "(session_id,process_id,cpu_percent,memory_bytes,memory_percent,thread_count,io_read_bytes,io_write_bytes) "
            "VALUES (:1,:2,:3,:4,:5,:6,:7,:8)", values
        )
        cursor.close()


class DetectionRepository:
    def has_open_alert(self, connection, process_id: int, check_type: str) -> bool:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT a.alert_id FROM security_alerts a "
            "JOIN detection_results d ON d.detection_result_id=a.detection_result_id "
            "WHERE d.process_id=:1 AND d.check_type=:2 AND a.status IN ('OPEN','INVESTIGATING') FETCH FIRST 1 ROWS ONLY",
            (process_id, check_type),
        )
        found = cursor.fetchone() is not None
        cursor.close()
        return found

    def add_finding(self, connection, session_id: int, process_id: int, finding) -> int:
        cursor = connection.cursor()
        detection_id = cursor.insert_returning_id(
            "INSERT INTO detection_results (session_id,process_id,check_type,verdict,risk_score,details) "
            "VALUES (:1,:2,:3,:4,:5,:6)",
            (session_id, process_id, finding.check_type, finding.verdict,
             finding.risk_score, json.dumps(finding.details, ensure_ascii=False, default=str)),
            "detection_result_id",
        )
        cursor.close()
        return detection_id

    def add_alert(self, connection, detection_id: int, severity: str) -> int:
        cursor = connection.cursor()
        alert_id = cursor.insert_returning_id(
            "INSERT INTO security_alerts (detection_result_id,severity,status) VALUES (:1,:2,'OPEN')",
            (detection_id, severity),
            "alert_id",
        )
        cursor.close()
        return alert_id


class AlertRepository:
    def count_open(self, connection) -> int:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE status IN ('OPEN','INVESTIGATING')")
        count = int(cursor.fetchone()[0])
        cursor.close()
        return count

    def list_recent(self, connection, limit: int = 100) -> list[dict]:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT a.alert_id,a.severity,a.status,a.created_at,a.resolved_at,"
            "p.pid,p.process_name,p.executable_path,d.check_type,d.risk_score,d.details "
            "FROM security_alerts a JOIN detection_results d ON d.detection_result_id=a.detection_result_id "
            "JOIN process_instances p ON p.process_id=d.process_id "
            "ORDER BY CASE a.status WHEN 'OPEN' THEN 0 WHEN 'INVESTIGATING' THEN 1 ELSE 2 END, "
            "a.created_at DESC FETCH FIRST :1 ROWS ONLY", (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        for row in rows:
            if isinstance(row.get("details"), str):
                try:
                    row["details"] = json.loads(row["details"])
                except json.JSONDecodeError:
                    pass
        return rows

    def set_status(self, connection, alert_id: int, status: str) -> None:
        allowed = {"OPEN", "INVESTIGATING", "RESOLVED", "DISMISSED"}
        if status not in allowed:
            raise ValueError("Unsupported alert status")
        cursor = connection.cursor()
        cursor.execute("SELECT alert_id FROM security_alerts WHERE alert_id=:1", (alert_id,))
        exists = cursor.fetchone() is not None
        if not exists:
            cursor.close()
            raise ValueError("Alert was not found")
        cursor.execute(
            "UPDATE security_alerts SET status=:1, resolved_at=:2 WHERE alert_id=:3",
            (status, datetime.now() if status in {"RESOLVED", "DISMISSED"} else None, alert_id),
        )
        cursor.close()


class AlertActionRepository:
    def add(self, connection, alert_id: int, action_type: str, notes: str = "",
            actor: str = "local-user") -> None:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO alert_actions (alert_id,action_type,actor,notes) VALUES (:1,:2,:3,:4)",
            (alert_id, action_type, actor[:100], notes or None),
        )
        cursor.close()
