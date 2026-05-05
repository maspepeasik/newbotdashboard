"""
PentestBot v2 — Logger
Configures structured logging with console + rotating file handlers.
Provides a factory for named loggers used across all modules.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

_initialized: bool = False

LOG_FORMAT     = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
DATE_FORMAT    = "%Y-%m-%d %H:%M:%S"
MAX_BYTES      = 20 * 1024 * 1024   # 20 MB
BACKUP_COUNT   = 7

# Noisy third-party loggers to silence
_SUPPRESS = [
    "httpx", "httpcore", "urllib3",
    "telegram", "telegram.ext",
    "asyncio", "aiohttp",
]


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    log_filename: str = "pentestbot.log",
) -> None:
    """Configure root logger once. Safe to call multiple times."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    numeric = getattr(logging, level.upper(), logging.INFO)
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    root = logging.getLogger()
    root.setLevel(numeric)

    # ── Console handler ────────────────────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(numeric)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # ── Rotating file handler ──────────────────────────────────────────
    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_dir / log_filename,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)  # Always verbose in file
        fh.setFormatter(formatter)
        root.addHandler(fh)

    # ── Suppress noisy libraries ───────────────────────────────────────
    for name in _SUPPRESS:
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Call setup_logging() before using."""
    return logging.getLogger(name)


class ScanLogger:
    """
    Per-scan logger that writes to both the global log
    and a dedicated per-scan log file.
    """

    def __init__(self, scan_id: str, log_dir: Path):
        self.scan_id = scan_id
        self._log_path = log_dir / f"scan_{scan_id}.log"
        self._logger = logging.getLogger(f"scan.{scan_id}")
        self._logger.setLevel(logging.DEBUG)

        # Dedicated file handler for this scan
        fh = logging.FileHandler(self._log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        self._logger.addHandler(fh)
        self._fh = fh

    @property
    def log_path(self) -> Path:
        return self._log_path

    def debug(self, msg: str, *args) -> None:
        self._logger.debug(msg, *args)

    def info(self, msg: str, *args) -> None:
        self._logger.info(msg, *args)

    def warning(self, msg: str, *args) -> None:
        self._logger.warning(msg, *args)

    def error(self, msg: str, *args) -> None:
        self._logger.error(msg, *args)

    def close(self) -> None:
        self._fh.close()
        self._logger.removeHandler(self._fh)
