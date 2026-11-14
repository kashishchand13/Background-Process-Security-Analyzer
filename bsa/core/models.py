from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class ProcessSnapshot:
    pid: int
    parent_pid: Optional[int]
    process_name: str
    executable_path: Optional[str]
    parent_name: Optional[str]
    username: Optional[str]
    state: Optional[str]
    create_time: float
    cpu_percent: float
    memory_bytes: int
    memory_percent: float
    thread_count: int
    priority_value: Optional[int]
    io_read_bytes: Optional[int] = None
    io_write_bytes: Optional[int] = None
    reputation_status: str = "UNKNOWN"
    risk_score: int = 0
    analysis_summary: str = "No active indicators"

    @property
    def instance_key(self) -> tuple[int, float]:
        return self.pid, round(self.create_time, 3)


@dataclass(slots=True)
class ReputationRule:
    rule_id: int
    process_name: str
    expected_path_prefix: Optional[str]
    sha256_hash: Optional[str]
    reputation: str
    reason: str


@dataclass(slots=True)
class Finding:
    check_type: str
    verdict: str
    risk_score: int
    severity: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProcessAnalysis:
    reputation_status: str
    risk_score: int
    summary: str
    findings: list[Finding]


@dataclass(slots=True)
class ScanSnapshot:
    processes: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    history: list[dict[str, Any]]
    summary: dict[str, Any]
    collected_at: datetime
