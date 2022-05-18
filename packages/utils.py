from datetime import datetime
from packages.config import offset
import logging
from packages.stats import dict_cleaning_windows
import packages.config as c

logger = logging.getLogger("IdsIpsAuthAnalyzer")


def ts2dt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def dict_cleaner(first_dict, second_dict):
    k_list = list(first_dict.keys())
    if len(k_list) > 9:
        cleaned = 0
        for i in range(offset):
            try:
                del first_dict[k_list[i]]
                del second_dict[k_list[i]]
                logger.info(f"Deleted key: {k_list[i]}")
                cleaned = cleaned + 1
            except Exception as e:
                logger.error(e)
        dict_cleaning_windows(c.statsd, "cleaned", cleaned)
    else:
        logger.error("Not enough data to clean")
        dict_cleaning_windows(c.statsd, "not_cleaned", 1)
    return first_dict, second_dict
