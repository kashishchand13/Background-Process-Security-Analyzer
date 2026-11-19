from contextlib import contextmanager
from typing import Iterator

import oracledb

from bsa.config import Settings


class OracleCursor:
    

    def __init__(self, raw_cursor, dictionary: bool = False):
        self._cursor = raw_cursor
        self._dictionary = dictionary

    def execute(self, statement, parameters=None):
        if parameters is None:
            return self._cursor.execute(statement)
        return self._cursor.execute(statement, parameters)

    def executemany(self, statement, parameters):
        return self._cursor.executemany(statement, parameters)

    def insert_returning_id(self, statement: str, parameters, id_column: str) -> int:
        """Execute an INSERT and return an Oracle identity using DML RETURNING."""
        bind_count = len(parameters)
        out_id = self._cursor.var(oracledb.DB_TYPE_NUMBER)
        statement = f"{statement} RETURNING {id_column} INTO :{bind_count + 1}"
        self._cursor.execute(statement, tuple(parameters) + (out_id,))
        value = out_id.getvalue()
        if isinstance(value, (tuple, list)):
            value = value[0] if value else None
        if value is None:
            raise RuntimeError(f"Oracle did not return the generated {id_column}")
        return int(value)

    def _as_dict(self, row):
        if row is None or not self._dictionary:
            return row
        names = [description[0].lower() for description in self._cursor.description]
        result = dict(zip(names, row))
        for key, value in result.items():
            # python-oracledb exposes CLOB columns as LOB objects; detach their text now.
            if hasattr(value, "read") and value.__class__.__name__ == "LOB":
                result[key] = value.read()
        return result

    def fetchone(self):
        return self._as_dict(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not self._dictionary:
            return rows
        return [self._as_dict(row) for row in rows]

    def close(self):
        return self._cursor.close()

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class OracleConnection:
    

    def __init__(self, raw_connection):
        self._connection = raw_connection

    def cursor(self, dictionary: bool = False):
        return OracleCursor(self._connection.cursor(), dictionary=dictionary)

    def __getattr__(self, name):
        return getattr(self._connection, name)


class Database:
    

    def __init__(self, settings: Settings):
        self._settings = settings

    @contextmanager
    def transaction(self) -> Iterator[OracleConnection]:
        connection = OracleConnection(oracledb.connect(**self._settings.oracle_kwargs()))
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def read_connection(self) -> Iterator[OracleConnection]:
        connection = OracleConnection(oracledb.connect(**self._settings.oracle_kwargs()))
        try:
            yield connection
        finally:
            connection.close()
