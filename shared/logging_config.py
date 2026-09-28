"""
ECS-aligned structured logging for the ZTA Overlay Network.
"""

import json
import logging
import os
import socket
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

# ─── Constants ────────────────────────────────────────────────────────────

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "zta.jsonl")

_TRACE_ID: ContextVar[str] = ContextVar("trace_id", default="")
HOSTNAME = socket.gethostname()


# ─── Service-name filter (attaches service name to every record) ─────────

class _ServiceNameFilter(logging.Filter):
    """Attach the service name to every record from this logger."""

    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name

    def filter(self, record: logging.LogRecord) -> bool:
        record.service_name = self.service_name
        return True


# ─── ECS-aligned JSON formatter ──────────────────────────────────────────

class ECSJsonFormatter(logging.Formatter):
    """Emits one JSON object per log record, with ECS-aligned top-level keys."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
        payload = {
            "@timestamp": ts.isoformat(timespec="milliseconds"),
            "log": {
                "level": record.levelname.lower(),
                "logger": record.name,
            },
            "service": {"name": getattr(record, "service_name", None) or record.name},
            "host": {"name": HOSTNAME},
            "message": record.getMessage(),
            "event": {"kind": "event"},
        }

        trace_id = _TRACE_ID.get()
        if trace_id:
            payload["trace"] = {"id": trace_id}

        event_action = getattr(record, "event_action", None)
        if event_action:
            payload["event"]["action"] = event_action
            parts = event_action.split(".")
            if len(parts) >= 1:
                payload["event"]["category"] = parts[0]
            if len(parts) >= 3:
                payload["event"]["outcome"] = parts[-1]

        ecs_extra = getattr(record, "ecs_extra", None)
        if isinstance(ecs_extra, dict):
            _deep_merge(payload, ecs_extra)

        return json.dumps(payload, ensure_ascii=False, default=str)


def _deep_merge(base: dict, overlay: dict) -> None:
    for k, v in overlay.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ─── Console formatter ────────────────────────────────────────────────────

class HumanFormatter(logging.Formatter):
    """Short readable line for local dev. Not for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        action = getattr(record, "event_action", "-")
        trace = _TRACE_ID.get()[:8] if _TRACE_ID.get() else "-"
        svc = getattr(record, "service_name", None) or record.name
        return (
            f"{ts} [{record.levelname:<5}] {svc:<10} "
            f"trace={trace} {action} :: {record.getMessage()}"
        )


# ─── Public API ───────────────────────────────────────────────────────────

def setup_logger(service_name: str, level: str | None = None) -> logging.Logger:
    """Configure and return a logger for the given service. Idempotent."""
    logger = logging.getLogger(service_name)
    if getattr(logger, "_zta_configured", False):
        return logger

    level = (level or os.environ.get("LOG_LEVEL", "INFO")).upper()
    logger.setLevel(level)
    logger.propagate = False

    os.makedirs(LOG_DIR, exist_ok=True)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(ECSJsonFormatter())
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(HumanFormatter())
    console_handler.setLevel(level)

    svc_filter = _ServiceNameFilter(service_name)
    file_handler.addFilter(svc_filter)
    console_handler.addFilter(svc_filter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger._zta_configured = True  # type: ignore[attr-defined]
    return logger


def set_trace_id(trace_id: str) -> None:
    _TRACE_ID.set(trace_id)


def get_trace_id() -> str:
    return _TRACE_ID.get()


def emit_event(logger: logging.Logger, event_action: str, message: str = "", **fields) -> None:
    """Emit a structured event. See module docstring for field conventions."""
    logger.info(
        message or event_action,
        extra={"event_action": event_action, "ecs_extra": fields},
    )