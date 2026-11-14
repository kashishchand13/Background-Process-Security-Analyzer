from __future__ import annotations

import json
from datetime import datetime

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QSizePolicy, QStackedWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from bsa.config import Settings
from bsa.services.alert_service import AlertManagementService
from bsa.services.monitoring_service import MonitoringWorker


APP_QSS = """
QMainWindow, QWidget#root { background: #11151c; color: #e8edf5; font-family: 'Segoe UI'; font-size: 10pt; }
QFrame#header { background: #181e28; border: 1px solid #2a3443; border-radius: 16px; }
QFrame#statCard { background: #1a222e; border: 1px solid #2c3747; border-radius: 16px; }
QFrame#panel { background: #171e28; border: 1px solid #2a3443; border-radius: 16px; }
QLabel#appTitle { font-size: 17pt; font-weight: 700; color: #f6f8fc; }
QLabel#muted { color: #9aa8bb; }
QLabel#cardValue { font-size: 23pt; font-weight: 700; color: #f5f8ff; }
QLabel#cardLabel { color: #aebbd0; font-size: 9pt; }
QLabel#sectionTitle { font-size: 13pt; font-weight: 650; color: #edf3fc; }
QLabel#statusPill { background: #163f39; border: 1px solid #246b5e; border-radius: 10px; padding: 5px 10px; color: #8eebce; font-weight: 600; }
QLineEdit, QComboBox { background: #101720; color: #edf2f9; border: 1px solid #354154; border-radius: 9px; padding: 9px 11px; selection-background-color: #2869d8; }
QComboBox QAbstractItemView { background: #171e28; selection-background-color: #2869d8; color: #edf2f9; }
QTableWidget { background: #141a23; alternate-background-color: #171f2a; color: #e3eaf5; gridline-color: #293443; border: 1px solid #2a3443; border-radius: 10px; selection-background-color: #233d60; selection-color: #ffffff; }
QHeaderView::section { background: #202a38; color: #b9c7db; border: none; border-right: 1px solid #303b4b; padding: 10px 7px; font-weight: 650; }
QTableWidget::item { padding: 6px; }
QPushButton { background: #26364a; color: #edf4ff; border: 1px solid #3b4f69; border-radius: 10px; padding: 9px 14px; font-weight: 600; }
QPushButton:hover { background: #304863; }
QPushButton:pressed { background: #1d2b3c; }
QPushButton#dockButton { background: transparent; border: 1px solid transparent; color: #a9b7ca; padding: 9px 18px; border-radius: 12px; min-width: 98px; }
QPushButton#dockButton:checked { background: #253a54; border: 1px solid #3d5d84; color: #f4f8ff; }
QPushButton#primaryButton { background: #2e72dd; border: 1px solid #4d8beb; }
QPushButton#primaryButton:hover { background: #3d80e8; }
QPushButton#dangerButton { background: #4b272d; border: 1px solid #7c3c45; }
QPushButton#dangerButton:hover { background: #5d2d35; }
QScrollBar:vertical { background: #141a23; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #3b4657; min-height: 25px; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
"""


def _item(value, tooltip: str | None = None) -> QTableWidgetItem:
    if value is None:
        value = "—"
    item = QTableWidgetItem(str(value))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if tooltip:
        item.setToolTip(tooltip)
    return item


def _friendly_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size:.0f} B"
        size /= 1024
    return f"{size:.1f} TB"


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings):
        super().__init__()
        self._settings = settings
        self._alert_service = AlertManagementService(settings)
        self._worker = MonitoringWorker(settings, self)
        self._process_rows: list[dict] = []
        self._alert_rows: list[dict] = []
        self._history_rows: list[dict] = []
        self._nav_buttons: list[QPushButton] = []
        self._init_ui()
        self._worker.snapshot_ready.connect(self._on_snapshot)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.status_changed.connect(self._on_status)
        self._worker.start()

    def _init_ui(self):
        self.setWindowTitle("Background Process Security Analyzer")
        self.resize(1420, 880)
        self.setMinimumSize(QSize(1100, 680))
        self.setStyleSheet(APP_QSS)

        root = QWidget()
        root.setObjectName("root")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(22, 18, 22, 14)
        root_layout.setSpacing(14)

        header = QFrame()
        header.setObjectName("header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 14, 18, 14)
        brand = QLabel("◈")
        brand.setStyleSheet("font-size: 28pt; color: #75a9ff; font-weight: 700;")
        header_layout.addWidget(brand)
        title_column = QVBoxLayout()
        title = QLabel("Background Process Security Analyzer")
        title.setObjectName("appTitle")
        subtitle = QLabel("Windows process visibility  ·  behavior signals  ·  local-first monitoring")
        subtitle.setObjectName("muted")
        title_column.addWidget(title)
        title_column.addWidget(subtitle)
        header_layout.addLayout(title_column, 1)
        self.status_label = QLabel("Starting")
        self.status_label.setObjectName("statusPill")
        header_layout.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        root_layout.addWidget(header)

        self.pages = QStackedWidget()
        self.dashboard_page = self._build_dashboard_page()
        self.processes_page = self._build_processes_page()
        self.alerts_page = self._build_alerts_page()
        self.history_page = self._build_history_page()
        for page in (self.dashboard_page, self.processes_page, self.alerts_page, self.history_page):
            self.pages.addWidget(page)
        root_layout.addWidget(self.pages, 1)

        dock = QFrame()
        dock.setObjectName("panel")
        dock_layout = QHBoxLayout(dock)
        dock_layout.setContentsMargins(10, 5, 10, 5)
        dock_layout.setSpacing(8)
        dock_layout.addStretch(1)
        for index, (label, page) in enumerate([
            ("⌂  Dashboard", 0), ("▦  Processes", 1), ("⚑  Alerts", 2), ("◷  History", 3)
        ]):
            button = QPushButton(label)
            button.setObjectName("dockButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=page: self._navigate(i))
            self._nav_buttons.append(button)
            dock_layout.addWidget(button)
        dock_layout.addStretch(1)
        root_layout.addWidget(dock, 0, Qt.AlignmentFlag.AlignHCenter)
        self.setCentralWidget(root)
        self._navigate(0)

    def _panel(self, title: str, subtitle: str | None = None) -> tuple[QFrame, QVBoxLayout]:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 13, 14, 14)
        layout.setSpacing(10)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        layout.addWidget(title_label)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("muted")
            layout.addWidget(sub)
        return panel, layout

    def _make_stat_card(self, label: str, value: str = "—", footnote: str = "") -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("statCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(5)
        heading = QLabel(label)
        heading.setObjectName("cardLabel")
        value_label = QLabel(value)
        value_label.setObjectName("cardValue")
        note = QLabel(footnote)
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(value_label)
        layout.addWidget(note)
        return card, value_label

    def _new_table(self, headers: list[str], compact: bool = False) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setMinimumSectionSize(70)
        table.verticalHeader().setDefaultSectionSize(33 if compact else 37)
        return table

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_processes, self.value_processes = self._make_stat_card("ACTIVE PROCESSES", "—", "Processes visible in the latest scan")
        self.card_suspicious, self.value_suspicious = self._make_stat_card("SUSPICIOUS", "—", "Needs human review; not a malware verdict")
        self.card_alerts, self.value_alerts = self._make_stat_card("OPEN ALERTS", "—", "Deduplicated while an alert remains open")
        self.card_threads, self.value_threads = self._make_stat_card("THREADS", "—", "Threads reported by the OS")
        for card in (self.card_processes, self.card_suspicious, self.card_alerts, self.card_threads):
            cards.addWidget(card, 1)
        layout.addLayout(cards)

        panel, panel_layout = self._panel("Live process overview", "Highest-risk processes are shown first. Select Processes for search and filtering.")
        self.dashboard_table = self._new_table(["PID", "PROCESS", "CPU %", "MEMORY", "THREADS", "REPUTATION", "RISK", "EXECUTABLE PATH"], compact=True)
        panel_layout.addWidget(self.dashboard_table, 1)
        layout.addWidget(panel, 1)
        return page

    def _build_processes_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        panel, panel_layout = self._panel("Process explorer", "OS concepts: process IDs, parent-child relationships, state, priority, threads, CPU, and memory.")
        tools = QHBoxLayout()
        self.process_search = QLineEdit()
        self.process_search.setPlaceholderText("Search by process name, PID, path, or parent…")
        self.process_search.textChanged.connect(self._render_process_table)
        self.reputation_filter = QComboBox()
        self.reputation_filter.addItems(["All reputations", "TRUSTED", "UNKNOWN", "SUSPICIOUS", "BLOCKLISTED"])
        self.reputation_filter.currentTextChanged.connect(self._render_process_table)
        tools.addWidget(self.process_search, 1)
        tools.addWidget(self.reputation_filter)
        panel_layout.addLayout(tools)
        self.process_table = self._new_table([
            "PID", "PROCESS", "PARENT", "STATE", "PRIORITY", "CPU %", "MEMORY", "THREADS", "REPUTATION", "RISK", "PATH"
        ])
        panel_layout.addWidget(self.process_table, 1)
        layout.addWidget(panel, 1)
        return page

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        panel, panel_layout = self._panel("Security alerts", "Alerts explain why a process was flagged. Validate evidence before deciding whether it is benign.")
        toolbar = QHBoxLayout()
        self.alert_help = QLabel("Select an alert to record an investigation outcome.")
        self.alert_help.setObjectName("muted")
        toolbar.addWidget(self.alert_help, 1)
        investigate = QPushButton("Investigating")
        investigate.clicked.connect(lambda: self._change_selected_alert("INVESTIGATING"))
        resolve = QPushButton("Resolve")
        resolve.setObjectName("primaryButton")
        resolve.clicked.connect(lambda: self._change_selected_alert("RESOLVED"))
        dismiss = QPushButton("Dismiss")
        dismiss.setObjectName("dangerButton")
        dismiss.clicked.connect(lambda: self._change_selected_alert("DISMISSED"))
        toolbar.addWidget(investigate)
        toolbar.addWidget(resolve)
        toolbar.addWidget(dismiss)
        panel_layout.addLayout(toolbar)
        self.alert_table = self._new_table(["ID", "SEVERITY", "CHECK", "PROCESS", "PID", "STATUS", "DETECTED", "DETAILS"])
        panel_layout.addWidget(self.alert_table, 1)
        layout.addWidget(panel, 1)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        panel, panel_layout = self._panel("Process history", "Records when a process is first observed and when it disappears between scans.")
        self.history_table = self._new_table(["EVENT", "PID", "PROCESS", "EXECUTABLE PATH", "DETAILS", "TIME"])
        panel_layout.addWidget(self.history_table, 1)
        layout.addWidget(panel, 1)
        return page

    def _navigate(self, index: int):
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self._nav_buttons):
            button.setChecked(i == index)

    def _on_status(self, text: str):
        self.status_label.setText(text)
        if text != "Monitoring":
            self.status_label.setStyleSheet("background:#47351d; border:1px solid #73562c; border-radius:10px; padding:5px 10px; color:#ffd993; font-weight:600;")
        else:
            self.status_label.setStyleSheet("")

    def _on_error(self, message: str):
        self.status_label.setText("Needs attention")
        QMessageBox.warning(self, "Security Analyzer", message)

    def _on_snapshot(self, data: dict):
        self._process_rows = data.get("processes", [])
        self._alert_rows = data.get("alerts", [])
        self._history_rows = data.get("history", [])
        summary = data.get("summary", {})
        self.value_processes.setText(str(summary.get("active_processes", 0)))
        self.value_suspicious.setText(str(summary.get("suspicious_processes", 0)))
        self.value_alerts.setText(str(summary.get("open_alerts", 0)))
        self.value_threads.setText(f"{summary.get('tracked_threads', 0):,}")
        self._render_process_table()
        self._render_table(self.dashboard_table, self._process_rows[:16], self._dashboard_values)
        self._render_table(self.alert_table, self._alert_rows, self._alert_values)
        self._render_table(self.history_table, self._history_rows, self._history_values)

    def _dashboard_values(self, row: dict) -> list:
        return [
            row.get("pid"), row.get("process_name"), f"{float(row.get('current_cpu_percent') or 0):.1f}",
            _friendly_bytes(row.get("current_memory_bytes")), row.get("thread_count"),
            row.get("reputation_status"), row.get("risk_score"), row.get("executable_path") or "—",
        ]

    def _render_process_table(self, *_args):
        if not hasattr(self, "process_table"):
            return
        query = self.process_search.text().strip().lower()
        selected_rep = self.reputation_filter.currentText()
        rows = []
        for row in self._process_rows:
            if selected_rep != "All reputations" and row.get("reputation_status") != selected_rep:
                continue
            searchable = " ".join(str(row.get(key) or "") for key in ("pid", "process_name", "parent_name", "executable_path", "process_state")).lower()
            if query and query not in searchable:
                continue
            rows.append(row)
        self._render_table(self.process_table, rows, self._process_values)

    def _process_values(self, row: dict) -> list:
        return [
            row.get("pid"), row.get("process_name"),
            f"{row.get('parent_name') or '—'} ({row.get('parent_pid') or '—'})",
            row.get("process_state"), row.get("priority_value"),
            f"{float(row.get('current_cpu_percent') or 0):.1f}",
            _friendly_bytes(row.get("current_memory_bytes")), row.get("thread_count"),
            row.get("reputation_status"), row.get("risk_score"), row.get("executable_path") or "—",
        ]

    def _alert_values(self, row: dict) -> list:
        details = row.get("details") or {}
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {"summary": details}
        created = row.get("created_at")
        return [
            row.get("alert_id"), row.get("severity"), row.get("check_type"),
            row.get("process_name"), row.get("pid"), row.get("status"),
            created.strftime("%Y-%m-%d %H:%M:%S") if isinstance(created, datetime) else created,
            details.get("summary", "Review the detailed evidence."),
        ]

    def _history_values(self, row: dict) -> list:
        occurred = row.get("occurred_at")
        return [
            row.get("event_type"), row.get("pid"), row.get("process_name"),
            row.get("executable_path") or "—", row.get("event_details") or "—",
            occurred.strftime("%Y-%m-%d %H:%M:%S") if isinstance(occurred, datetime) else occurred,
        ]

    def _render_table(self, table: QTableWidget, rows: list[dict], converter):
        selected_value = None
        current_row = table.currentRow()
        if current_row >= 0 and table.item(current_row, 0) is not None:
            selected_value = table.item(current_row, 0).text()
        table.setUpdatesEnabled(False)
        table.setRowCount(len(rows))
        selected_new_row = -1
        for r_index, row in enumerate(rows):
            values = converter(row)
            for c_index, value in enumerate(values):
                tooltip = str(value) if c_index in (2, 7, 10) else None
                cell = _item(value, tooltip)
                if table in (self.process_table, self.dashboard_table):
                    label = str(value)
                    if label == "SUSPICIOUS" or label == "BLOCKLISTED":
                        cell.setForeground(QColor("#ff9d9d"))
                    elif label == "TRUSTED":
                        cell.setForeground(QColor("#8fe0c2"))
                    elif label in ("HIGH", "CRITICAL"):
                        cell.setForeground(QColor("#ff9d9d"))
                elif table is self.alert_table and c_index == 1:
                    if str(value) in ("HIGH", "CRITICAL"):
                        cell.setForeground(QColor("#ff9d9d"))
                    elif str(value) == "MEDIUM":
                        cell.setForeground(QColor("#ffd080"))
                table.setItem(r_index, c_index, cell)
            if selected_value is not None and str(values[0]) == selected_value:
                selected_new_row = r_index
        table.resizeColumnsToContents()
        if table.columnCount() > 0:
            table.horizontalHeader().setStretchLastSection(True)
        table.setUpdatesEnabled(True)
        if selected_new_row >= 0:
            table.selectRow(selected_new_row)

    def _change_selected_alert(self, status: str):
        row_index = self.alert_table.currentRow()
        if row_index < 0:
            QMessageBox.information(self, "Select an alert", "Select an alert row first.")
            return
        id_cell = self.alert_table.item(row_index, 0)
        if not id_cell:
            return
        try:
            alert_id = int(id_cell.text())
            self._alert_service.update_status(alert_id, status, f"Status updated to {status} from desktop dashboard.")
            self.alert_help.setText(f"Alert #{alert_id} marked {status.lower()}.")
            # Reflect the change immediately; the monitoring worker will refresh full data shortly.
            if row_index < len(self._alert_rows):
                for alert in self._alert_rows:
                    if int(alert.get("alert_id")) == alert_id:
                        alert["status"] = status
                        break
            self._render_table(self.alert_table, self._alert_rows, self._alert_values)
        except Exception as exc:
            QMessageBox.warning(self, "Could not update alert", str(exc))

    def closeEvent(self, event):
        if self._worker.isRunning():
            self.status_label.setText("Stopping")
            self._worker.stop()
        event.accept()
