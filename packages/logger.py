import logging
from os import getenv
from time import time
import sys


def init_logger():
    logger = logging.getLogger("IdsIpsAuthAnalyzer")
    if getenv("DEBUG", None):
        logging_level = logging.DEBUG
        formatter = logging.Formatter(
            "%(asctime)s : %(name)3s : %(levelname)8s : %(message)s [%(pathname)s %(funcName)s() `line %(lineno)d`]"
        )
    else:
        logging_level = logging.INFO
        formatter = logging.Formatter(
            "%(asctime)s : %(name)3s : %(levelname)8s : %(message)s"
        )

    logger.setLevel(logging_level)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    log_to_file = bool(getenv("LOGTOFILE", ""))
    logger.debug(f"LOGTOFILE: {log_to_file}")
    if log_to_file:
        log_name = f"devel/log_IdsIpsAuthAnalyzer_run_{int(time())}.log"
        logger.debug(f"Logging to file: `{log_name}`")
        fh = logging.FileHandler(log_name)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    logger.info(
        f"Loger init - DONE; logging level: {logging_level}; logging to file: {log_to_file}"
    )
    return
