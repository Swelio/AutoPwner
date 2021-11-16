"""
Provide logging configurable methods.
"""

import logging
from logging import LogRecord
from typing import Union

__all__ = ["get_logger", "ColoredFormatted"]

LOG_FORMAT = (
    "%(levelname)s::%(asctime)s::%(name)s::%(filename)s::%(lineno)d::%(message)s"
)
LOG_LEVEL = "DEBUG"


def get_logger(
    logger_name: str,
    log_level: Union[int, str] = LOG_LEVEL,
    output_format: str = LOG_FORMAT,
    console_output: bool = True,
    color_console: bool = True,
    log_file: str = None,
) -> logging.Logger:
    """Setup logger and attach handlers on it."""

    if isinstance(log_level, str):
        log_level = logging.getLevelName(log_level)

    assert log_level in [
        logging.CRITICAL,
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    ], "Invalid log level."
    assert isinstance(output_format, str) and output_format, "Invalid log format."
    assert isinstance(console_output, bool), "Invalid console output mode."
    assert log_file is None or (
        isinstance(log_file, str) and log_file and not log_file.endswith(".py")
    ), "Invalid log file"
    assert console_output or log_file, "Logs have no output."

    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    handlers = set()

    # Setup handlers and attach them to logger
    if console_output is True:
        console_handler = logging.StreamHandler()
        if color_console is True:
            console_handler.setFormatter(ColoredFormatted(output_format))
        else:
            console_handler.setFormatter(logging.Formatter(output_format))
        handlers.add(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(output_format))
        handlers.add(file_handler)

    for handler in handlers:
        logger.addHandler(handler)

    return logger


class ColoredFormatted(logging.Formatter):
    """Color console outputs according to log level."""

    COLOR_SEQUENCE = r"\033[0;{color}m\]"
    DEFAULT_SEQUENCE = r"\033[0;0m\]"

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)

    LEVEL_COLORS = {
        logging.CRITICAL: RED,
        logging.ERROR: RED,
        logging.WARNING: YELLOW,
        logging.INFO: WHITE,
        logging.DEBUG: BLUE,
    }

    def format(self, record: LogRecord) -> str:
        message = super().format(record)
        # get level color and apply it on message
        level_color = self.COLOR_SEQUENCE.format(
            color=self.LEVEL_COLORS[record.levelno]
        )
        return f"{level_color}{message}{self.DEFAULT_SEQUENCE}"
