from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections import defaultdict

from bsa.config import Settings
from bsa.core.hash_cache import ExecutableHashCache
from bsa.core.models import Finding, ProcessAnalysis, ProcessSnapshot, ReputationRule
from bsa.core.path_utils import executable_is_in_directory, path_is_within


SYSTEM_CRITICAL_PATHS = {
    "svchost.exe": ("System32", "SysWOW64"),
    "lsass.exe": ("System32",),
    "services.exe": ("System32",),
    "winlogon.exe": ("System32",),
    "csrss.exe": ("System32",),
    "wininit.exe": ("System32",),
    "smss.exe": ("System32",),
    "spoolsv.exe": ("System32",),
    "dwm.exe": ("System32",),
    "taskhostw.exe": ("System32", "SysWOW64"),
    "runtimebroker.exe": ("System32", "SysWOW64"),
    "explorer.exe": ("",),
}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SCRIPTING_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe"
}


def _severity(score: int) -> str:
    if score >= 95:
        return "CRITICAL"
    if score >= 80:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"


def _finding(check_type: str, score: int, summary: str, **details) -> Finding:
    return Finding(
        check_type=check_type,
        verdict="FAIL" if score >= 80 else "WARNING",
        risk_score=score,
        severity=_severity(score),
        details={"summary": summary, **details},
    )


class DetectionRule(ABC):
    """Strategy interface for independently testable security checks."""

    @abstractmethod
    def evaluate(self, process: ProcessSnapshot, context: dict) -> Finding | None:
        raise NotImplementedError


class PathVerificationDetector(DetectionRule):
    def evaluate(self, process: ProcessSnapshot, context: dict) -> Finding | None:
        path = process.executable_path
        if not path:
            return None
        name = process.process_name.lower()
        if name in SYSTEM_CRITICAL_PATHS:
            return None  # Handled by the more specific spoofing detector.
        matching_rules = [r for r in context["rules_by_name"].get(name, []) if r.expected_path_prefix]
        if not matching_rules:
            return None
        if any(path_is_within(path, rule.expected_path_prefix) for rule in matching_rules):
            return None
        expected = sorted({r.expected_path_prefix for r in matching_rules if r.expected_path_prefix})
        return _finding(
            "PATH_VERIFICATION", 82,
            "Executable path does not match the configured reputation rule.",
            pid=process.pid, process_name=process.process_name, executable_path=path,
            expected_path_prefixes=expected,
        )


class ProcessSpoofingDetector(DetectionRule):
    def __init__(self, windows_dir: str | None = None):
        windows_dir = windows_dir or os.environ.get("WINDIR", r"C:\Windows")
        self._expected_paths: dict[str, list[str]] = {}
        for name, suffixes in SYSTEM_CRITICAL_PATHS.items():
            self._expected_paths[name] = [os.path.join(windows_dir, suffix) if suffix else windows_dir for suffix in suffixes]

    def evaluate(self, process: ProcessSnapshot, context: dict) -> Finding | None:
        name = process.process_name.lower()
        if name not in self._expected_paths or not process.executable_path:
            return None
        expected = self._expected_paths[name]
        if any(executable_is_in_directory(process.executable_path, prefix) for prefix in expected):
            return None
        return _finding(
            "PROCESS_SPOOFING", 96,
            "A Windows system-process name is executing outside its expected directory; investigate possible impersonation.",
            pid=process.pid, process_name=process.process_name,
            executable_path=process.executable_path, expected_path_prefixes=expected,
        )


class ProcessHierarchyDetector(DetectionRule):
    def evaluate(self, process: ProcessSnapshot, context: dict) -> Finding | None:
        parent = (process.parent_name or "").lower()
        child = process.process_name.lower()
        if parent in OFFICE_PARENTS and child in SCRIPTING_CHILDREN:
            return _finding(
                "PROCESS_HIERARCHY", 78,
                "An Office application launched a scripting or command interpreter; this can be legitimate but warrants review.",
                pid=process.pid, process_name=process.process_name,
                parent_pid=process.parent_pid, parent_name=process.parent_name,
            )
        return None


class ResourceBehaviorDetector(DetectionRule):
    def __init__(self, cpu_threshold: float = 85, memory_threshold: float = 35):
        self._cpu_threshold = cpu_threshold
        self._memory_threshold = memory_threshold

    def evaluate(self, process: ProcessSnapshot, context: dict) -> Finding | None:
        cpu_high = process.cpu_percent >= self._cpu_threshold
        memory_high = process.memory_percent >= self._memory_threshold
        if not cpu_high and not memory_high:
            return None
        score = 82 if cpu_high and memory_high else (72 if cpu_high else 66)
        reasons = []
        if cpu_high:
            reasons.append(f"CPU {process.cpu_percent:.1f}% >= {self._cpu_threshold:.1f}%")
        if memory_high:
            reasons.append(f"memory {process.memory_percent:.1f}% >= {self._memory_threshold:.1f}%")
        return _finding(
            "RESOURCE_BEHAVIOR", score,
            "Unusually high resource consumption was observed; review the process and its recent history.",
            pid=process.pid, process_name=process.process_name,
            cpu_percent=round(process.cpu_percent, 2),
            memory_percent=round(process.memory_percent, 2), reasons=reasons,
        )


class ReputationMatcher:
    def __init__(self, hash_cache: ExecutableHashCache):
        self._hash_cache = hash_cache

    def classify(self, process: ProcessSnapshot, rules: list[ReputationRule]) -> tuple[str, Finding | None]:
        named_rules = [r for r in rules if r.process_name.lower() == process.process_name.lower()]
        if not named_rules:
            return "UNKNOWN", None
        if not process.executable_path:
            # Do not label a process malicious merely because Windows denied path access.
            explicit_name_only = [
                r for r in named_rules
                if not r.expected_path_prefix and not r.sha256_hash
                and r.reputation in {"SUSPICIOUS", "BLOCKLISTED"}
            ]
            if not explicit_name_only:
                return "UNKNOWN", None
            chosen = max(explicit_name_only, key=lambda r: 1 if r.reputation == "SUSPICIOUS" else 2)
            score = 100 if chosen.reputation == "BLOCKLISTED" else 84
            finding = _finding(
                "REPUTATION_MATCHING", score,
                "The process name matches an explicit local reputation rule, but its executable path is unavailable.",
                pid=process.pid, process_name=process.process_name, rule_id=chosen.rule_id,
                reason=chosen.reason, executable_path=None,
            )
            return chosen.reputation, finding

        matched: list[ReputationRule] = []
        hash_mismatch = False
        for rule in named_rules:
            path_ok = not rule.expected_path_prefix or path_is_within(process.executable_path, rule.expected_path_prefix)
            if not path_ok:
                continue
            if rule.sha256_hash:
                actual_hash = self._hash_cache.sha256(process.executable_path)
                if actual_hash is None:
                    continue
                if actual_hash.lower() != rule.sha256_hash.lower():
                    hash_mismatch = True
                    continue
            matched.append(rule)

        if matched:
            # The most restrictive matching record takes precedence.
            order = {"BLOCKLISTED": 3, "SUSPICIOUS": 2, "TRUSTED": 1}
            chosen = max(matched, key=lambda r: order.get(r.reputation, 0))
            if chosen.reputation == "BLOCKLISTED":
                finding = _finding(
                    "REPUTATION_MATCHING", 100,
                    "The executable matches a locally configured blocklist rule.",
                    pid=process.pid, process_name=process.process_name, rule_id=chosen.rule_id,
                    reason=chosen.reason, executable_path=process.executable_path,
                )
                return "BLOCKLISTED", finding
            if chosen.reputation == "SUSPICIOUS":
                finding = _finding(
                    "REPUTATION_MATCHING", 84,
                    "The executable matches a locally configured suspicious-process rule.",
                    pid=process.pid, process_name=process.process_name, rule_id=chosen.rule_id,
                    reason=chosen.reason, executable_path=process.executable_path,
                )
                return "SUSPICIOUS", finding
            return "TRUSTED", None

        if hash_mismatch:
            finding = _finding(
                "REPUTATION_MATCHING", 88,
                "The executable's SHA-256 hash differs from the configured reference hash.",
                pid=process.pid, process_name=process.process_name,
                executable_path=process.executable_path,
            )
            return "SUSPICIOUS", finding

        # A known name with a mismatching path is suspicious; the path/spoofing rule provides details.
        return "SUSPICIOUS", None


class SecurityAnalyzer:
    """Coordinates detection strategies and aggregates a per-process risk result."""

    def __init__(self, settings: Settings):
        hash_cache = ExecutableHashCache(settings.max_hash_file_mb)
        self._reputation_matcher = ReputationMatcher(hash_cache)
        self._rules: list[DetectionRule] = [
            PathVerificationDetector(),
            ProcessSpoofingDetector(),
            ProcessHierarchyDetector(),
            ResourceBehaviorDetector(settings.cpu_alert_threshold, settings.memory_alert_threshold),
        ]

    @staticmethod
    def _context(snapshots: list[ProcessSnapshot], rules: list[ReputationRule]) -> dict:
        by_name = defaultdict(list)
        for rule in rules:
            by_name[rule.process_name.lower()].append(rule)
        return {
            "rules_by_name": by_name,
            "process_by_pid": {p.pid: p for p in snapshots},
        }

    def analyze(self, snapshots: list[ProcessSnapshot], rules: list[ReputationRule]) -> dict[int, ProcessAnalysis]:
        context = self._context(snapshots, rules)
        analyses: dict[int, ProcessAnalysis] = {}
        for process in snapshots:
            findings: list[Finding] = []
            reputation_status, reputation_finding = self._reputation_matcher.classify(process, rules)
            if reputation_finding:
                findings.append(reputation_finding)
            for detector in self._rules:
                finding = detector.evaluate(process, context)
                if finding:
                    findings.append(finding)
            max_score = max((f.risk_score for f in findings), default=0)
            if any(f.risk_score >= 95 for f in findings):
                reputation_status = "SUSPICIOUS" if reputation_status != "BLOCKLISTED" else reputation_status
            elif any(f.risk_score >= 60 for f in findings) and reputation_status in ("TRUSTED", "UNKNOWN"):
                reputation_status = "SUSPICIOUS"
            summary = "; ".join(dict.fromkeys(f.details.get("summary", f.check_type) for f in findings))
            if not summary:
                summary = "No active indicators" if reputation_status == "TRUSTED" else f"No alert; reputation: {reputation_status.lower()}"
            process.reputation_status = reputation_status
            process.risk_score = max_score
            process.analysis_summary = summary
            analyses[process.pid] = ProcessAnalysis(reputation_status, max_score, summary, findings)
        return analyses
