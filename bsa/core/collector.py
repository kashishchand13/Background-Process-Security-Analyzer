from __future__ import annotations

from typing import Optional
import platform

import psutil

from bsa.core.models import ProcessSnapshot


class ProcessCollector:
    """Interface for collectors; another OS collector can be substituted later."""

    def collect(self) -> list[ProcessSnapshot]:
        raise NotImplementedError


class PsutilProcessCollector(ProcessCollector):
    """Collects read-only process facts. Access-denied fields are left empty."""

    @staticmethod
    def _safe(callable_, default=None):
        try:
            return callable_()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, ValueError):
            return default

    def collect(self) -> list[ProcessSnapshot]:
        raw = []
        parent_names: dict[int, str] = {}
        for proc in psutil.process_iter():
            pid = proc.pid
            name = self._safe(proc.name, f"pid-{pid}") or f"pid-{pid}"
            ppid = self._safe(proc.ppid, None)
            create_time = self._safe(proc.create_time, None)
            if create_time is None:
                continue
            exe = self._safe(proc.exe, None)
            username = self._safe(proc.username, None)
            state = self._safe(proc.status, None)
            cpu = self._safe(lambda: proc.cpu_percent(interval=None), 0.0) or 0.0
            memory_info = self._safe(proc.memory_info, None)
            memory_bytes = int(getattr(memory_info, "rss", 0) or 0)
            memory_percent = self._safe(proc.memory_percent, 0.0) or 0.0
            threads = self._safe(proc.num_threads, 0) or 0
            priority = self._safe(proc.nice, None)
            io = self._safe(proc.io_counters, None)
            read_bytes = int(getattr(io, "read_bytes", 0)) if io else None
            write_bytes = int(getattr(io, "write_bytes", 0)) if io else None
            snapshot = ProcessSnapshot(
                pid=int(pid), parent_pid=int(ppid) if ppid is not None else None,
                process_name=str(name), executable_path=exe,
                parent_name=None, username=username, state=state,
                create_time=float(create_time), cpu_percent=max(0.0, float(cpu)),
                memory_bytes=memory_bytes, memory_percent=max(0.0, float(memory_percent)),
                thread_count=int(threads), priority_value=int(priority) if isinstance(priority, (int, float)) else None,
                io_read_bytes=read_bytes, io_write_bytes=write_bytes,
            )
            raw.append(snapshot)
            parent_names[snapshot.pid] = snapshot.process_name

        for snapshot in raw:
            if snapshot.parent_pid is not None:
                snapshot.parent_name = parent_names.get(snapshot.parent_pid)
        return raw
