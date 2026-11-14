"""Apply database/schema.sql to the configured Oracle schema owner."""
from pathlib import Path
import re
import sys

import oracledb

from bsa.config import Settings


def _error_code(exc) -> int | None:
    if getattr(exc, "code", None) is not None:
        return exc.code
    if exc.args and getattr(exc.args[0], "code", None) is not None:
        return exc.args[0].code
    return None


def main() -> int:
    settings = Settings()
    schema_path = Path(__file__).parent / "database" / "schema.sql"
    script = schema_path.read_text(encoding="utf-8")
    script = re.sub(r"(?m)^\s*--.*$", "", script)
    statements = [part.strip() for part in script.split(";") if part.strip()]
    connection = None
    created = 0
    existing = 0
    try:
        connection = oracledb.connect(**settings.oracle_kwargs())
        cursor = connection.cursor()
        for statement in statements:
            try:
                cursor.execute(statement)
                created += 1
            except oracledb.DatabaseError as exc:
                # ORA-00955: a table/index/other object with that name already exists.
                if _error_code(exc) == 955:
                    existing += 1
                    continue
                raise
        cursor.close()
        print(f"Oracle schema ready in service '{settings.db_service_name}'.")
        print(f"DDL statements created: {created}; existing objects skipped: {existing}.")
        print("If a table already exists with an older structure, review/migrate it manually before starting the app.")
        return 0
    except Exception as exc:
        print(f"Oracle schema setup failed: {exc}", file=sys.stderr)
        print(
            "Check that the Oracle listener/service is running, BSA_DB_SERVICE_NAME is correct, "
            "and the configured schema user can create tables/indexes.",
            file=sys.stderr,
        )
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
