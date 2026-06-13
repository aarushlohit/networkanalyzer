from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }, default=str)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_output: bool = False,
) -> logging.Logger:
    root = logging.getLogger("vulnsync")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    if json_output or log_file:
        fmt = JSONFormatter()
    else:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        root.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"vulnsync.{name}")
