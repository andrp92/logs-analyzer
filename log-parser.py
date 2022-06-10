import requests
import logging
import re

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Main:
    def __init__(self):
        self.logs_url = "https://pastebin.com/raw/gstGCJv4"
        self.file_name = "puppet_access_ssl.log"
        self.sshd_config_fetched_count = 0
        self.apache_return_code_not_200_count = 0
        self.total_return_code_not_200_count = 0
        self.total_ip_address_report = 0
        self.ip_address_report = {}
        self.fetch_logs()
        self.parse_logs()
        self.show_results()

    def fetch_logs(self):
        log_file = requests.get(self.logs_url)
        with open(self.file_name, "wb") as f:
            f.write(log_file.content)
        logger.info("Fetched logs from %s", self.logs_url)
        return log_file

    def parse_logs(self):
        with open(self.file_name, "r") as f:
            http_code_regex_pattern = '" (\w+) \w+'
            ip_regex_pattern = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            sshd_config_string = "GET /production/file_metadata/modules/ssh/sshd_config"

            for line in f:
                if sshd_config_string in line:
                    self.sshd_config_fetched_count += 1
                    if not "200" in re.search(http_code_regex_pattern, line).group(1):
                        apache_return_code_not_200_count += 1
                elif not "200" in re.search(http_code_regex_pattern, line).group(1):
                    self.total_return_code_not_200_count += 1
                elif "PUT /dev/report/" in line:
                    self.total_ip_address_report += 1
                    ip_address = re.search(ip_regex_pattern, line).group(1)
                    if ip_address in self.ip_address_report:
                        self.ip_address_report[ip_address] += 1
                    else:
                        self.ip_address_report[ip_address] = 1

    def show_results(self):
        logger.info(
            "Total times SSHD config was fetched: {}".format(
                self.sshd_config_fetched_count
            )
        )
        logger.info(
            "Out of previous request, total times Apache return code was other than 200: {}".format(
                self.apache_return_code_not_200_count
            )
        )
        logger.info(
            "Total number of times Apache returned other than 200: {}".format(
                self.total_return_code_not_200_count
            )
        )
        logger.info(
            "Total number of times a PUT requests was sent to /dev/report/: {}".format(
                self.total_ip_address_report
            )
        )
        for ip_address, count in self.ip_address_report.items():
            logger.info("IP address {} was reported {} times".format(ip_address, count))


if __name__ == "__main__":
    Main()
