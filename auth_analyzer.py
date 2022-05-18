# coding: utf-8
#!/usr/bin/python3

import logging
from packages.kafkaConsumer import get_data
from concurrent.futures import ProcessPoolExecutor

logger = logging.getLogger("IdsIpsAuthAnalyzer")


def create_process_pool():
    executor = ProcessPoolExecutor(max_workers=1)
    return executor


if __name__ == "__main__":
    logger.info("kafka Consumer start")
    p_ex = create_process_pool()
    get_data(p_ex)
