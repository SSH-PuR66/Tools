from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(*, verbose: bool = False) -> None:
    root = logging.getLogger("rangecheck")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    if root.handlers:
        return

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("%(levelname)s  %(name)s  %(message)s"))
    root.addHandler(console)

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    file_handler = RotatingFileHandler(
        log_dir / "rangecheck.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s  %(levelname)s  %(name)s  %(message)s")
    )
    root.addHandler(file_handler)
