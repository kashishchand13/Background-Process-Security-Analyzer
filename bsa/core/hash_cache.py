from __future__ import annotations

import hashlib
import os
from typing import Optional


class ExecutableHashCache:
    """Hashes on demand only; results are cached by path, size, and modification time."""

    def __init__(self, max_file_mb: int = 100):
        self._max_bytes = max_file_mb * 1024 * 1024
        self._cache: dict[tuple[str, int, int], str] = {}

    def sha256(self, path: str | None) -> Optional[str]:
        if not path:
            return None
        try:
            size = os.path.getsize(path)
            modified = os.path.getmtime(path)
            if size > self._max_bytes:
                return None
            key = (os.path.normcase(os.path.abspath(path)), size, int(modified * 1000))
            if key in self._cache:
                return self._cache[key]
            digest = hashlib.sha256()
            with open(path, "rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)
            value = digest.hexdigest()
            if len(self._cache) > 2000:
                self._cache.clear()
            self._cache[key] = value
            return value
        except (OSError, PermissionError):
            return None
