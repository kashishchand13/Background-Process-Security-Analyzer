from __future__ import annotations

import os
import threading
import time
from datetime import datetime

from PySide6.QtCore import QThread, Signal

from bsa.config import Settings
from bsa.core.collector import PsutilProcessCollector
from bsa.core.detectors import SecurityAnalyzer
from bsa.db.database import Database
from bsa.db.repositories import (
    AlertRepository, DetectionRepository, HistoryRepository, MetricsRepository,
    ProcessRepository, ReputationRuleRepository, SessionRepository, SystemRepository,
)


class MonitoringWorker(QThread):
    """Runs process collection/database writes away from the Qt UI thread."""

    snapshot_ready = Signal(dict)
    error_occurred = Signal(str)
    status_changed = Signal(str)

    def __init__(self, settings: Settings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()
        self.wait(7000)

    def run(self):
        database = Database(self._settings)
        system_repo = SystemRepository()
        session_repo = SessionRepository()
        process_repo = ProcessRepository()
        history_repo = HistoryRepository()
        metrics_repo = MetricsRepository()
        rule_repo = ReputationRuleRepository()
        detection_repo = DetectionRepository()
        alert_repo = AlertRepository()
        collector = PsutilProcessCollector()
        analyzer = SecurityAnalyzer(self._settings)
        system_id = None
        session_id = None
        previous: dict[tuple[int, float], tuple[int, object]] = {}
        last_metric_write = 0.0

        try:
            with database.transaction() as connection:
                system_id = system_repo.get_or_create(connection)
                rule_repo.seed_builtin_rules(connection)
                session_id = session_repo.start(connection, system_id)
            self.status_changed.emit("Monitoring")

            while not self._stop_event.is_set():
                cycle_start = time.monotonic()
                snapshots = collector.collect()
                with database.transaction() as connection:
                    process_repo.mark_inactive(connection, system_id)
                    rules = rule_repo.list_enabled(connection)
                    analyses = analyzer.analyze(snapshots, rules)
                    process_id_by_pid = process_repo.upsert_many(connection, system_id, snapshots)

                    current: dict[tuple[int, float], tuple[int, object]] = {}
                    for process in snapshots:
                        process_id = process_id_by_pid.get(process.pid)
                        if process_id is None:
                            continue
                        key = process.instance_key
                        current[key] = (process_id, process)
                        if key not in previous:
                            history_repo.add_event(
                                connection, session_id, process_id, "FIRST_SEEN", process,
                                "Process observed for the first time in this session.",
                            )

                        analysis = analyses.get(process.pid)
                        if not analysis:
                            continue
                        for finding in analysis.findings:
                            if detection_repo.has_open_alert(connection, process_id, finding.check_type):
                                continue
                            detection_id = detection_repo.add_finding(connection, session_id, process_id, finding)
                            detection_repo.add_alert(connection, detection_id, finding.severity)

                    for key, (process_id, old_process) in previous.items():
                        if key not in current:
                            history_repo.add_event(
                                connection, session_id, process_id, "PROCESS_EXITED", old_process,
                                "Process was present in the previous scan and is absent from the current scan.",
                            )

                    now_mono = time.monotonic()
                    if now_mono - last_metric_write >= self._settings.metrics_interval_seconds:
                        top_processes = sorted(
                            snapshots, key=lambda p: p.cpu_percent + p.memory_percent, reverse=True
                        )[:max(1, self._settings.metrics_top_n)]
                        metrics_repo.insert_many(connection, session_id, process_id_by_pid, top_processes)
                        last_metric_write = now_mono

                    session_repo.update_count(connection, session_id, len(snapshots))
                    process_rows = process_repo.list_active(connection)
                    alert_rows = alert_repo.list_recent(connection, 150)
                    history_rows = history_repo.list_recent(connection, 100)
                    open_alerts = alert_repo.count_open(connection)
                    suspicious = sum(1 for p in snapshots if p.reputation_status in ("SUSPICIOUS", "BLOCKLISTED"))
                    summary = {
                        "active_processes": len(snapshots),
                        "suspicious_processes": suspicious,
                        "open_alerts": open_alerts,
                        "tracked_threads": sum(p.thread_count for p in snapshots),
                    }
                    self.snapshot_ready.emit({
                        "processes": process_rows,
                        "alerts": alert_rows,
                        "history": history_rows,
                        "summary": summary,
                        "collected_at": datetime.now().strftime("%H:%M:%S"),
                    })
                    previous = current

                elapsed = time.monotonic() - cycle_start
                self._stop_event.wait(max(0.5, self._settings.scan_interval_seconds - elapsed))

        except Exception as exc:
            self.error_occurred.emit(
                f"Monitoring stopped: {exc}\nCheck the Oracle listener/service, schema, and BSA database settings."
            )
            self.status_changed.emit("Error")
        finally:
            if session_id is not None:
                try:
                    with database.transaction() as connection:
                        session_repo.end_with_connection(
                            connection, session_id, "ERROR" if self._stop_event.is_set() is False else "STOPPED"
                        )
                except Exception as exc:
                    self.error_occurred.emit(f"Could not close scan session cleanly: {exc}")
            if self._stop_event.is_set():
                self.status_changed.emit("Stopped")
