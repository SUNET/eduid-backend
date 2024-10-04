import logging
import sys

from loguru import Logger
from loguru import logger as loguru_logger


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists
        level: str | int
        try:
            level = loguru_logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find calling function
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__ and frame.f_back:
            frame = frame.f_back
            depth += 1

        loguru_logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def init_logging() -> Logger:
    loguru_logger.remove()
    fmt = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <7}</level> | <cyan>{module: <11}</cyan>:"
        "<cyan> {line: <3} </cyan> | <level>{message}</level>"
    )
    loguru_logger.add(sys.stderr, format=fmt, level="DEBUG")
    loguru_logger.debug("Logging initialized")
    return loguru_logger


def audit_log(msg: str) -> None:
    # Find calling function
    frame, depth = logging.currentframe(), 2
    while frame.f_code.co_filename == logging.__file__:
        assert frame.f_back  # please mypy
        frame = frame.f_back
        depth += 1

    loguru_logger.opt(depth=depth).info(f"AUDIT: {msg}")
