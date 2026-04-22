import logging
import sys

FORMATTER = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s",'
                              '"logger": "%(name)s", "thread": "%(threadName)s", "message": "%(message)s"}')
DEFAULT_LOG_LEVEL = logging.INFO


def set_log_level(lvl: str):
    if lvl.upper() == "DEBUG":
        log_level = logging.DEBUG
    elif lvl.upper() == "INFO":
        log_level = logging.INFO
    elif lvl.upper() == "WARNING" or lvl.upper() == "WARN":
        log_level = logging.WARNING
    elif lvl.upper() == "ERROR":
        log_level = logging.ERROR
    elif lvl.upper() == "CRITICAL":
        log_level = logging.CRITICAL
    else:
        log_level = DEFAULT_LOG_LEVEL
    logging.basicConfig(level=log_level)


def get_console_handler():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.addHandler(get_console_handler())
    # with this pattern, it's rarely necessary to propagate the error up to parent
    logger.propagate = False
    return logger
