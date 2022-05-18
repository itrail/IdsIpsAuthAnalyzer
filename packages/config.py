# coding: utf-8
#!/usr/bin/python3

import logging
from os import getenv
from datetime import datetime as dt
from packages.logger import init_logger
from statsd import StatsClient

# LOGGER INIT
init_logger()

start_time = dt.now()
logger = logging.getLogger("IdsIpsAuthAnalyzer")
# LOGGER TESTS
logger.info("--- INFO TEST")
logger.debug("--- DEBUG TEST")
logger.warning("--- WARNING TEST")
logger.error("--- ERROR TEST")
logger.critical("--- CRITICAL TEST")

# ENV VARIABLES
# tajne

ONE_DAY_IN_SECONDS = 86400
STATS_PREFIX = "IDS_IPS_auth_analyzer"
STATS_VERSION = "v1"

TABLE_NAME = [
    "blocked_trials",
    "protocols_trials",
    "bruteforce",
    "ips",
    "despite_locks",
]

# STATSD INIT
statsd = StatsClient(host, int(statsport), STATS_PREFIX)
