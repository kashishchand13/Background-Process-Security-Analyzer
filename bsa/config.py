from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    db_host: str = os.getenv("BSA_DB_HOST", "127.0.0.1")
    db_port: int = int(os.getenv("BSA_DB_PORT", "1521"))
    db_service_name: str = os.getenv("BSA_DB_SERVICE_NAME", "XEPDB1")
    db_user: str = os.getenv("BSA_DB_USER", "BSA")
    db_password: str = os.getenv("BSA_DB_PASSWORD", "")
    scan_interval_seconds: int = int(os.getenv("BSA_SCAN_INTERVAL", "5"))
    metrics_interval_seconds: int = int(os.getenv("BSA_METRICS_INTERVAL", "30"))
    metrics_top_n: int = int(os.getenv("BSA_METRICS_TOP_N", "25"))
    cpu_alert_threshold: float = float(os.getenv("BSA_CPU_ALERT_THRESHOLD", "85"))
    memory_alert_threshold: float = float(os.getenv("BSA_MEMORY_ALERT_THRESHOLD", "35"))
    max_hash_file_mb: int = int(os.getenv("BSA_MAX_HASH_FILE_MB", "100"))

    def oracle_kwargs(self) -> dict:
        import oracledb

        return {
            "user": self.db_user,
            "password": self.db_password,
            "dsn": oracledb.makedsn(
                self.db_host,
                self.db_port,
                service_name=self.db_service_name,
            ),
            "tcp_connect_timeout": 5,
        }
