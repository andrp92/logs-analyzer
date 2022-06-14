import requests
import logging
import re
import os

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class LogsAnalyser:
    def __init__(self, url):
        self.logs_url = url
        self.file_path = "/tmp/puppet_access_ssl.log"
        self.sshd_config_fetched_count = 0
        self.apache_return_code_not_200_count = 0
        self.total_return_code_not_200_count = 0
        self.total_ip_address_report = 0
        self.ip_address_report = {}
        self.fetch_logs()
        self.parse_logs()
        self.show_results()
        self.clean_up()

    def fetch_logs(self):
        logger.info("Fetching logs")
        log_file = requests.get(self.logs_url)
        with open(self.file_path, "wb") as f:
            f.write(log_file.content)
        logger.info("Fetched logs from %s", self.logs_url)

    def parse_logs(self):
        logger.info("Parsing logs")
        with open(self.file_path, "r") as f:
            http_code_regex_pattern = '" (\w+) \w+'
            ip_regex_pattern = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            get_sshd_config_request = (
                "GET /production/file_metadata/modules/ssh/sshd_config"
            )
            put_dev_report_request = "PUT /dev/report/"

            for index, line in enumerate(f):
                http_code_match = re.search(http_code_regex_pattern, line)
                ip_match = re.search(ip_regex_pattern, line)
                line_is_invalid = http_code_match is None or ip_match is None
                if line_is_invalid:
                    logger.warning("Line {} has an Invalid format".format(index))
                    continue
                if get_sshd_config_request in line:
                    self.sshd_config_fetched_count += 1
                    if not "200" in http_code_match.group(1):
                        self.apache_return_code_not_200_count += 1
                elif not "200" in http_code_match.group(1):
                    self.total_return_code_not_200_count += 1
                elif put_dev_report_request in line:
                    self.total_ip_address_report += 1
                    ip_address = ip_match.group(1)
                    if ip_address in self.ip_address_report:
                        self.ip_address_report[ip_address] += 1
                    else:
                        self.ip_address_report[ip_address] = 1
            self.total_return_code_not_200_count += self.apache_return_code_not_200_count
        logger.info("Parsed logs")

    def show_results(self):
        logger.info("Showing results")
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
            "Total number of times Apache return code was other than 200: {}".format(
                self.total_return_code_not_200_count
            )
        )
        logger.info(
            "Total number of times a PUT requests was sent to /dev/report/: {}".format(
                self.total_ip_address_report
            )
        )
        logger.info("Number of requests sent to /dev/report/ by IP address:")
        for ip_address, count in self.ip_address_report.items():
            logger.info(f"{ip_address:15} ==> {count}")

    def clean_up(self):
        os.remove(self.file_path)
        logger.info("Cleaned up log file")


if __name__ == "__main__":
    LogsAnalyser("https://pastebin.com/raw/gstGCJv4")
