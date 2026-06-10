import json
import logging
import os
import sys

from app.core.config import settings


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def setup_logging():
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if settings.LOG_FORMAT == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s"
            ))
        root.addHandler(handler)

    root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    if os.getenv("BACKUP_SUPPRESS_PARAMIKO_TRANSPORT_TRACEBACKS", "1").strip().lower() in {"1", "true", "yes", "on"}:
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
