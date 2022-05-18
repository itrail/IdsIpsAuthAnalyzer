import logging
from packages.config import STATS_PREFIX, STATS_VERSION


logger = logging.getLogger("IdsIpsAuthAnalyzer")


def table_insert_status(statsd, operation, status):
    logger.debug(f"send table save: `{operation}` `{status}`")
    statsd.incr(
        f"{STATS_PREFIX}.{STATS_VERSION}.database.{operation}.{status}",
        1,
    )
    return


def tasks_status(statsd, operation, status):
    logger.debug(f"send task status: `{operation}` `{status}`")
    statsd.incr(
        f"{STATS_PREFIX}.{STATS_VERSION}.task.{operation}.{status}",
        1,
    )
    return


def messages_status(statsd, operation, status):
    logger.debug(f"send message status: `{operation}` `{status}`")
    statsd.incr(
        f"{STATS_PREFIX}.{STATS_VERSION}.messages.{operation}.{status}",
        1,
    )
    return


def dict_cleaning_windows(statsd, operation, value):
    logger.debug(f"send sum of windows removed from dict: `{operation}` `{value}`")
    statsd.gauge(
        f"{STATS_PREFIX}.{STATS_VERSION}.windows.{operation}",
        value,
    )
    return


def result_data(statsd, operation, value):
    logger.debug(f"send stts of result data: `{operation}` `{value}`")
    statsd.gauge(
        f"{STATS_PREFIX}.{STATS_VERSION}.result.{operation}",
        value,
    )
    return
