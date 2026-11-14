import ntpath


def normalize_windows_path(path: str | None) -> str | None:
    if not path:
        return None
    return ntpath.normcase(ntpath.normpath(path.strip().strip('"')))


def path_is_within(path: str | None, prefix: str | None) -> bool:
    """Case-insensitive Windows path-prefix test with directory-boundary safety."""
    normalized_path = normalize_windows_path(path)
    normalized_prefix = normalize_windows_path(prefix)
    if not normalized_path or not normalized_prefix:
        return False
    if normalized_path == normalized_prefix:
        return True
    return normalized_path.startswith(normalized_prefix.rstrip("\\") + "\\")


def executable_is_in_directory(path: str | None, directory: str | None) -> bool:
    """True only when the executable's direct parent directory matches exactly."""
    normalized_path = normalize_windows_path(path)
    normalized_directory = normalize_windows_path(directory)
    if not normalized_path or not normalized_directory:
        return False
    return ntpath.dirname(normalized_path).rstrip("\\") == normalized_directory.rstrip("\\")
