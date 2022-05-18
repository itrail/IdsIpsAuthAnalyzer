# coding: utf-8
#!/usr/bin/python3

import logging, time
from features.IdsIpsAuthAnalyzerSenses import IdsIpsAuthAnalyzerSenses
from packages.database_controller import create_cursor, insert_data
from packages.stats import table_insert_status, tasks_status, result_data
from math import ceil
import packages.config as c

logger = logging.getLogger("IdsIpsAuthAnalyzer")


def process_data(login_trials, ip_trials):
    logger.info(" --- RESULT PART --- START ---")
    logger.debug(" DATADICTS:")
    mydb, mycursor = create_cursor()

    login_trials = process_result_data(login_trials)
    ip_trials = process_result_data(ip_trials)
    senses = IdsIpsAuthAnalyzerSenses()

    (
        blocked_trials,
        protocols_trials,
        bruteforce,
    ) = senses.observe_the_accounts(login_trials)
    ip_bruteforce_trials = senses.hear_the_ips(ip_trials)
    logger.debug("Gupowanie po loginach --- stop")

    logger.info(
        " --- ACCOUNTS: LOCKED WITH LOCK OR WITH PASSWORD RESET WITH MANY LOG IN TRIALS ---"
    )
    if blocked_trials:
        blt_query = """INSERT INTO blocked_login (login, attemps, ips, countries, correct_passwords, authorizations, locks) 
            VALUES (%(login)s, %(attemps)s, %(ips)s, %(countries)s, %(correct_passwords)s, %(authorizations)s, %(locks)s);"""
        try:
            insert_data(mydb, mycursor, blt_query, blocked_trials)
            status = "OK"
        except Exception as e:
            logger.error(e)
            status = "FAILED"
        table_insert_status(c.statsd, "blocked_trials.insert.status", status)
    logger.info(
        f"{len(blocked_trials)} accounts with lock or with password reset log in trials"
    )
    result_data(c.statsd, "blocked_trials", len(blocked_trials))

    logger.info(
        " --- ACCOUNTS WITH AUTHENTICATION VIA PROTOCOLS DESPITE DISABLED PROTOCOLS!!! --- "
    )
    if protocols_trials:
        pt_query = """INSERT INTO protocols_login (login, attemps, ips, countries, correct_passwords, authorizations, locks) 
        VALUES (%(login)s, %(attemps)s, %(ips)s, %(countries)s, %(correct_passwords)s, %(authorizations)s, %(locks)s);"""
        try:
            insert_data(mydb, mycursor, pt_query, protocols_trials)
            status = "OK"
        except Exception as e:
            logger.error(e)
            status = "FAILED"
        table_insert_status(c.statsd, "protocols_trials.insert.status", status)
    logger.info(
        f"{len(protocols_trials)} accounts with protocols authentication with disabled protocols"
    )
    result_data(c.statsd, "protocols_trials", len(protocols_trials))

    logger.info(
        f" --- ACCOUNTS WITH POSSIBLE BRUTEFORCE TRIALS WITH CORRECT PASSWORDS ---"
    )
    if bruteforce:
        bf_query = """INSERT INTO bruteforce_login (login, attemps, ips, countries, correct_passwords, authorizations, locks) 
        VALUES (%(login)s, %(attemps)s, %(ips)s, %(countries)s, %(correct_passwords)s, %(authorizations)s, %(locks)s);"""
        try:
            insert_data(mydb, mycursor, bf_query, bruteforce)
            status = "OK"
        except Exception as e:
            logger.error(e)
            status = "FAILED"
        table_insert_status(c.statsd, "bruteforce.insert.status", status)
    logger.info(
        f"{len(bruteforce)} bruteforce trials to accounts with correct password"
    )
    result_data(c.statsd, "bruteforce", len(bruteforce))

    logger.info(" --- IPS: POSSIBLE BRUTEFORCE TRIALS ---")
    if ip_bruteforce_trials:
        ips_query = """INSERT INTO bruteforce_ip (ip, country, attemps, logins, correct_passwords, authorizations, locks) 
        VALUES (%(ip)s, %(country)s, %(attemps)s, %(logins)s, %(correct_passwords)s, %(authorizations)s, %(locks)s);"""
        try:
            insert_data(mydb, mycursor, ips_query, ip_bruteforce_trials)
            status = "OK"
        except Exception as e:
            logger.error(e)
            status = "FAILED"
        table_insert_status(c.statsd, "ips.insert.status", status)
    logger.info(
        f"{len(ip_bruteforce_trials)} ips with probability of bruteforce trials"
    )
    result_data(c.statsd, "ip_bruteforce_trials", len(ip_bruteforce_trials))

    logger.info(" --- ACCOUNTS LOCKED BY locker WITH AUTHORIZATION!!! --- ")
    auth_desp_bl = senses.sniff_the_deceit(login_trials)
    if auth_desp_bl:
        try:
            for row in auth_desp_bl:
                mycursor.execute(
                    f"INSERT INTO lockered_login (login, ip) VALUES ('{row[0]}', '{row[1]}');"
                )
                mydb.commit()
            status = "OK"
        except Exception as e:
            logger.error(e)
            status = "FAILED"
        table_insert_status(c.statsd, "despite_locks.insert.status", status)
    logger.info(len(auth_desp_bl))
    result_data(c.statsd, "auth_desp_bl", len(auth_desp_bl))

    logger.info(" --- RESULT PART --- END ---")
    logger.debug(" -- PROCESS QUEUE DONE")
    tasks_status(c.statsd, "task.done.status", "OK")
    return


def process_kafkas_entry(entry, login_trials, ip_trials, now, end_time):
    login_trials = process_login_trials(entry, login_trials, now, end_time)
    ip_trials = process_ip_trials(entry, ip_trials, now)
    return login_trials, ip_trials


def process_login_trials(entry, trials, now, end_time):
    if entry["user"]["login"] in trials[now]:
        pass
    else:
        trials[now][entry["user"]["login"]] = {}

    if "attemps" in trials[now][entry["user"]["login"]]:
        trials[now][entry["user"]["login"]]["attemps"] = (
            trials[now][entry["user"]["login"]]["attemps"] + 1
        )
    else:
        trials[now][entry["user"]["login"]]["attemps"] = 1

    if "countries" in trials[now][entry["user"]["login"]]:
        pass
    else:
        trials[now][entry["user"]["login"]]["countries"] = {}

    if entry["geodata"]["country"] in trials[now][entry["user"]["login"]]["countries"]:
        trials[now][entry["user"]["login"]]["countries"][
            entry["geodata"]["country"]
        ] = (
            trials[now][entry["user"]["login"]]["countries"][
                entry["geodata"]["country"]
            ]
            + 1
        )
    else:
        trials[now][entry["user"]["login"]]["countries"][
            entry["geodata"]["country"]
        ] = 1

    if "ips" in trials[now][entry["user"]["login"]]:
        pass
    else:
        trials[now][entry["user"]["login"]]["ips"] = {}

    if entry["client"]["ip"] in trials[now][entry["user"]["login"]]["ips"]:
        trials[now][entry["user"]["login"]]["ips"][entry["client"]["ip"]] = (
            trials[now][entry["user"]["login"]]["ips"][entry["client"]["ip"]] + 1
        )
    else:
        trials[now][entry["user"]["login"]]["ips"][entry["client"]["ip"]] = 1

    if entry["authentication"] == "PASS":
        if "correct_passwords" in trials[now][entry["user"]["login"]]:
            trials[now][entry["user"]["login"]]["correct_passwords"] = (
                trials[now][entry["user"]["login"]]["correct_passwords"] + 1
            )
        else:
            trials[now][entry["user"]["login"]]["correct_passwords"] = 1

    if entry["authorization"] == "PASS":
        if "authorizations" in trials[now][entry["user"]["login"]]:
            trials[now][entry["user"]["login"]]["authorizations"] = (
                trials[now][entry["user"]["login"]]["authorizations"] + 1
            )
        else:
            trials[now][entry["user"]["login"]]["authorizations"] = 1
        if "authorization_ips" in trials[now][entry["user"]["login"]]:
            if (
                entry["client"]["ip"]
                not in trials[now][entry["user"]["login"]]["authorization_ips"]
            ):
                trials[now][entry["user"]["login"]]["authorization_ips"].append(
                    entry["client"]["ip"]
                )
        else:
            trials[now][entry["user"]["login"]]["authorization_ips"] = [
                entry["client"]["ip"]
            ]

    if entry["authorization"] == "PASS" and time.time() >= end_time - (
        c.cron_time * 60
    ):
        if "last_seen" in trials[now][entry["user"]["login"]]:
            if entry["timestamp"] > trials[now][entry["user"]["login"]]["last_seen"]:
                trials[now][entry["user"]["login"]]["last_seen"] = entry["timestamp"]
        else:
            trials[now][entry["user"]["login"]]["last_seen"] = entry["timestamp"]

    if entry["authentication"] == "PASS" and entry["locker"] == "FAIL":
        if "locks" in trials[now][entry["user"]["login"]]:
            trials[now][entry["user"]["login"]]["locks"] = (
                trials[now][entry["user"]["login"]]["locks"] + 1
            )
        else:
            trials[now][entry["user"]["login"]]["locks"] = 1

    #'auth_protocol': 'pop3'
    protocols = ["imap", "pop3", "smtp"]
    if (
        entry["authorization"] == "FAIL"
        and entry["auth_protocol"] in protocols
        and entry["authentication"] == "PASS"
        and entry["locker"] == "PASS"
    ):
        if "protocols_fails" in trials[now][entry["user"]["login"]]:
            pass
        else:
            trials[now][entry["user"]["login"]]["protocols_fails"] = 1
    return trials


def process_ip_trials(entry, trials, now):
    if entry["client"]["ip"] in trials[now]:
        pass
    else:
        trials[now][entry["client"]["ip"]] = {"country": entry["geodata"]["country"]}

    if "attemps" in trials[now][entry["client"]["ip"]]:
        trials[now][entry["client"]["ip"]]["attemps"] = (
            trials[now][entry["client"]["ip"]]["attemps"] + 1
        )
    else:
        trials[now][entry["client"]["ip"]]["attemps"] = 1

    if "logins" in trials[now][entry["client"]["ip"]]:
        pass
    else:
        trials[now][entry["client"]["ip"]]["logins"] = {}

    if entry["user"]["login"] in trials[now][entry["client"]["ip"]]["logins"]:
        trials[now][entry["client"]["ip"]]["logins"][entry["user"]["login"]] = (
            trials[now][entry["client"]["ip"]]["logins"][entry["user"]["login"]] + 1
        )
    else:
        trials[now][entry["client"]["ip"]]["logins"][entry["user"]["login"]] = 1

    if entry["authentication"] == "PASS":
        if "correct_passwords" in trials[now][entry["client"]["ip"]]:
            trials[now][entry["client"]["ip"]]["correct_passwords"] = (
                trials[now][entry["client"]["ip"]]["correct_passwords"] + 1
            )
        else:
            trials[now][entry["client"]["ip"]]["correct_passwords"] = 1

    if entry["authorization"] == "PASS":
        if "authorizations" in trials[now][entry["client"]["ip"]]:
            trials[now][entry["client"]["ip"]]["authorizations"] = (
                trials[now][entry["client"]["ip"]]["authorizations"] + 1
            )
        else:
            trials[now][entry["client"]["ip"]]["authorizations"] = 1

    if entry["authentication"] == "PASS" and entry["locker"] == "FAIL":
        if "locks" in trials[now][entry["client"]["ip"]]:
            trials[now][entry["client"]["ip"]]["locks"] = (
                trials[now][entry["client"]["ip"]]["locks"] + 1
            )
        else:
            trials[now][entry["client"]["ip"]]["locks"] = 1

    return trials


def process_result_data(login_trials):
    result = {}
    for minute in login_trials.keys():
        for column_to_group in login_trials[minute]:
            if column_to_group in result:
                pass
            else:
                result[column_to_group] = {}
            for key, value in login_trials[minute][column_to_group].items():
                if key == "ips":
                    if key in result[column_to_group]:
                        pass
                    else:
                        result[column_to_group][key] = {}
                    for ip, counts in login_trials[minute][column_to_group][
                        key
                    ].items():
                        if ip in result[column_to_group][key]:
                            result[column_to_group][key][ip] = (
                                result[column_to_group][key][ip] + counts
                            )
                        else:
                            result[column_to_group][key][ip] = counts
                elif key == "countries":
                    if key in result[column_to_group]:
                        pass
                    else:
                        result[column_to_group][key] = {}
                    for country, counts in login_trials[minute][column_to_group][
                        key
                    ].items():
                        if country in result[column_to_group][key]:
                            result[column_to_group][key][country] = (
                                result[column_to_group][key][country] + counts
                            )
                        else:
                            result[column_to_group][key][country] = counts
                elif key == "last_seen":
                    if key in result[column_to_group]:
                        if result[column_to_group][key] < value:
                            result[column_to_group][key] = value
                    else:
                        result[column_to_group][key] = value
                elif key == "logins":
                    if key in result[column_to_group]:
                        pass
                    else:
                        result[column_to_group][key] = {}
                    for login, counts in login_trials[minute][column_to_group][
                        key
                    ].items():
                        if login in result[column_to_group][key]:
                            result[column_to_group][key][login] = (
                                result[column_to_group][key][login] + counts
                            )
                        else:
                            result[column_to_group][key][login] = counts
                elif key == "country":
                    if key not in result[column_to_group]:
                        result[column_to_group][key] = value
                elif key == "authorization_ips":
                    if key not in result[column_to_group]:
                        result[column_to_group][key] = value
                else:
                    if key in result[column_to_group]:
                        result[column_to_group][key] = (
                            result[column_to_group][key] + value
                        )
                    else:
                        result[column_to_group][key] = value
    return result
