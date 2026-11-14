from bsa.config import Settings
from bsa.db.database import Database
from bsa.db.repositories import AlertActionRepository, AlertRepository


class AlertManagementService:
    """Application service for changing alert status and writing an audit record."""

    def __init__(self, settings: Settings):
        self._database = Database(settings)
        self._alerts = AlertRepository()
        self._actions = AlertActionRepository()

    def update_status(self, alert_id: int, status: str, notes: str = "") -> None:
        action_for_status = {
            "INVESTIGATING": "INVESTIGATING",
            "RESOLVED": "RESOLVED",
            "DISMISSED": "DISMISSED",
            "OPEN": "REOPENED",
        }
        with self._database.transaction() as connection:
            self._alerts.set_status(connection, alert_id, status)
            self._actions.add(connection, alert_id, action_for_status[status], notes)
