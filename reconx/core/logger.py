import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logger(log_file: str = "reconx.log", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("reconx")
    logger.setLevel(level.upper())
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    console = RichHandler(rich_tracebacks=True, show_path=False)
    console.setLevel(level.upper())
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(level.upper())
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(file_handler)
    return logger


def get_logger() -> logging.Logger:
    logger = logging.getLogger("reconx")
    if not logger.handlers:
        setup_logger()
    return logger
