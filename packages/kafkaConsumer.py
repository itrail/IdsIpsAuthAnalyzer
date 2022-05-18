from datetime import datetime
from packages import essentials
import packages.config as c
from kafka import KafkaConsumer
import json
import logging
import time
from packages.utils import ts2dt, dict_cleaner
from packages.stats import tasks_status, messages_status

logger = logging.getLogger("IdsIpsAuthAnalyzer")


def get_consumer(group):
    return KafkaConsumer(
        c.TOPIC,
        group_id=group,
        bootstrap_servers=c.HOSTS,
        auto_offset_reset="current",
        auto_commit_interval_ms=20000,
    )


def drop_last_minute(data_list, start_time):
    return [elem for elem in data_list if elem["datetime"] > start_time]


def get_end_time(start_time):
    end_time = start_time + (c.minutes_in_window * 60)
    return end_time


def get_data(process_executor):
    login_trials = {}
    ip_trials = {}
    try:
        consumer = get_consumer("IDS_IPS_auth_analyzer")
        consumer.poll()
        consumer.seek_to_end()
    except Exception as e:
        logger.error(e)
    start_time = time.time()
    end_time = get_end_time(start_time)
    time_window = f"'{ts2dt(start_time)}' - '{ts2dt(end_time)}'"
    logger.info(time_window)
    for message in consumer:
        try:
            entry = json.loads(message.value)
        except Exception as e:
            logger.error(e)
            messages_status(c.statsd, "message.status", "JSON_ERROR")
            continue
        # if entry['auth_protocol'] != '':
        # pomijane pust ip, bo nic nie wnoszą jeżeli poprawne logowania to nie ma problemu, a jeżli błędne to podbija statystyki o 1 ip
        if entry["client"]["ip"] != "" and entry["auth_protocol"] != "":
            messages_status(c.statsd, "message.status", "OK")
            now = datetime.now().strftime("%Y-%m-%d %H:%M")
            if now not in login_trials:
                login_trials[now] = {}
            if now not in ip_trials:
                ip_trials[now] = {}
            login_trials, ip_trials = essentials.process_kafkas_entry(
                entry, login_trials, ip_trials, now, end_time
            )
        if time.time() >= end_time:
            logger.info("processing windows - start")
            task = process_executor.submit(
                essentials.process_data, login_trials, ip_trials
            )
            tasks_status(c.statsd, "task.started.status", "OK")
            login_trials, ip_trials = dict_cleaner(login_trials, ip_trials)
            start_time = start_time + ((c.offset) * 60)
            # obliczanie nowego końca okna
            end_time = get_end_time(start_time)
            time_window = f"'{ts2dt(start_time)}' - '{ts2dt(end_time)}'"
            logger.info(time_window)
            logger.info("processing windows - stop")
    return
