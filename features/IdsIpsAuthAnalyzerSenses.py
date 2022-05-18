from packages.stats import tasks_status
import requests, logging
import json
import packages.config as c

logger = logging.getLogger("IdsIpsAuthAnalyzer")


class IdsIpsAuthAnalyzerSenses:
    def observe_the_accounts(self, login_trials):
        bruteforce = []
        blocked_acl_reset = []
        protocols_fails = []
        for login in login_trials.keys():
            ips = len(login_trials[login]["ips"].keys())
            countries = len(login_trials[login]["countries"].keys())
            if "authorizations" in login_trials[login]:
                pass
            else:
                login_trials[login]["authorizations"] = 0
            if "correct_passwords" in login_trials[login]:
                pass
            else:
                login_trials[login]["correct_passwords"] = 0
            if "locks" in login_trials[login]:
                pass
            else:
                login_trials[login]["locks"] = 0
            condition_trial = (
                login_trials[login]["authorizations"]
                <= 0.6 * login_trials[login]["attemps"]
                and login_trials[login]["attemps"] > 50
            )
            condition_lock = (
                condition_trial
                and login_trials[login]["correct_passwords"] >= 1
                and login_trials[login]["correct_passwords"]
                > login_trials[login]["locks"]
                and login_trials[login]["correct_passwords"]
                > login_trials[login]["authorizations"]
            )
            condition_bf = (
                condition_trial
                and not condition_lock
                and login_trials[login]["correct_passwords"] >= 1
                and login_trials[login]["correct_passwords"]
                < 0.6 * login_trials[login]["attemps"]
            )
            row = {
                "login": login,
                "attemps": login_trials[login]["attemps"],
                "ips": ips,
                "countries": countries,
                "correct_passwords": login_trials[login]["correct_passwords"],
                "authorizations": login_trials[login]["authorizations"],
                "locks": login_trials[login]["locks"],
            }

            if condition_trial and "protocols_fails" in login_trials[login]:
                protocols_fails.append(row)
            elif condition_lock and "protocols_fails" not in login_trials[login]:
                blocked_acl_reset.append(row)

            if condition_bf:
                bruteforce.append(row)

        return blocked_acl_reset, protocols_fails, bruteforce

    def hear_the_ips(self, ip_trials):
        bruteforce_trials = []
        for ip in ip_trials.keys():
            logins = len(ip_trials[ip]["logins"].keys())
            if "authorizations" in ip_trials[ip]:
                pass
            else:
                ip_trials[ip]["authorizations"] = 0
            if "correct_passwords" in ip_trials[ip]:
                pass
            else:
                ip_trials[ip]["correct_passwords"] = 0
            if "locks" in ip_trials[ip]:
                pass
            else:
                ip_trials[ip]["locks"] = 0
            condition_trial = (
                ip_trials[ip]["attemps"] > 1000
                and ip_trials[ip]["authorizations"] < 0.6 * ip_trials[ip]["attemps"]
            )
            row = {
                "ip": ip,
                "country": ip_trials[ip]["country"],
                "attemps": ip_trials[ip]["attemps"],
                "logins": logins,
                "correct_passwords": ip_trials[ip]["correct_passwords"],
                "authorizations": ip_trials[ip]["authorizations"],
                "locks": ip_trials[ip]["locks"],
            }

            if condition_trial:
                bruteforce_trials.append(row)

        return bruteforce_trials

    # zwraca konta zablokowane w ostatnie Y minut, maksymalnie Y minut wstecz do czasu z przyszłości
    def get_locked_accounts(self, address):
        locked_accounts = []
        try:
            response = requests.get(address, timeout=60)
            if response.status_code == 200:
                tasks_status(c.statsd, "locker_response", "OK")
                logger.info("Response from locker collected")
                json_data = json.loads(response.text)
                for row in json_data:
                    if row["name"] == "IP_User":
                        locked_accounts.append(
                            [
                                row["abf"]["user"],
                                int(row["expires"]) - c.offset * 60,
                                row["abf"]["ip"],
                            ]
                        )
            else:
                tasks_status(c.statsd, "locker_response", "FAILED")
        except Exception as e:
            logger.error(f"Problem with request to locker - {e}")
            tasks_status(c.statsd, "locker_response", "FAILED")
        return locked_accounts

    def sniff_the_deceit(self, login_trials):
        locked_accounts = self.get_locked_accounts(c.locker_ADDRESS[0])
        authorizations_despite_block = []
        if locked_accounts:
            to_check = []
            # konta na które udało się zalogować w ostatnich Y minut
            for login in login_trials.keys():
                if "last_seen" in login_trials[login]:
                    to_check.append(
                        [
                            login,
                            login_trials[login]["last_seen"],
                            login_trials[login]["authorization_ips"],
                        ],
                    )
            authorizations_despite_block = [
                [account[0], account[1]]
                for login in to_check
                for account in locked_accounts
                if account[0] == login[0]
                and account[1] >= login[1]
                and account[2] in login[2]
            ]
        return list(set(authorizations_despite_block))
