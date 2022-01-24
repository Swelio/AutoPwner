"""
Provide logging configurable methods.
"""
import datetime
import logging
import os.path
from logging import LogRecord
from typing import Union

__all__ = ["get_logger"]


def get_logger(
    logger_name: str,
    log_level: Union[int, str] = logging.DEBUG,
    output_format: str = "%(levelname)s::%(asctime)s::%(name)s::%(message)s",
    color_console: bool = True,
    log_dir: str = None,
) -> logging.Logger:
    """Setup class_logger and attach handlers on it."""

    if isinstance(log_level, str):
        log_level = logging.getLevelName(log_level)

    if log_level not in [
        logging.CRITICAL,
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    ]:
        raise ValueError(f"Unknown log level: '{log_level}'")

    logger = logging.getLogger(logger_name)

    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.DEBUG)

    # Setup handlers and attach them to class_logger
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    if color_console is True:
        console_handler.setFormatter(ColoredFormatter(output_format))
    else:
        console_handler.setFormatter(logging.Formatter(output_format))

    logger.addHandler(console_handler)

    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(
            log_dir, datetime.datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S") + ".log"
        )
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        # set file log level to DEBUG in order to save all logs
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(output_format))

        logger.addHandler(file_handler)

    return logger


class ColoredFormatter(logging.Formatter):
    """Color console outputs according to log level."""

    COLOR_SEQUENCE = "\033[0;{color}m"
    DEFAULT_SEQUENCE = "\033[0;0m"

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)

    LEVEL_COLORS = {
        logging.CRITICAL: RED,
        logging.ERROR: RED,
        logging.WARNING: YELLOW,
        logging.INFO: BLUE,
        logging.DEBUG: CYAN,
    }

    def format(self, record: LogRecord) -> str:
        message = super().format(record)
        # get level color and apply it on message
        level_color = self.COLOR_SEQUENCE.format(
            color=self.LEVEL_COLORS[record.levelno]
        )
        return f"{level_color}{message}{self.DEFAULT_SEQUENCE}"
