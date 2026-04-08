# audit_log.py
import json
from datetime import datetime

class AuditLogger:
    """
    Logs actions without including PHI.
    """

    def log(self, action: str, user_id: str, metadata: dict = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "user_id": user_id,
            "metadata": metadata or {}
        }
        # Print structured log (or write to file in real use)
        print(json.dumps(entry, indent=2))