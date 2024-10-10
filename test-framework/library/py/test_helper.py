###################################################
# Automated Testing Framework for Network Analytics
# Wrapper class for common test case functionality
# nikolaos.tsokas@swisscom.com 22/02/2024
###################################################

import logging
import library.py.test_tools as test_tools
import library.py.helpers as helpers
import library.py.scripts as scripts
from library.py.test_params import KModuleParams
from typing import List

logger = logging.getLogger(__name__)


class KTestHelper:

    def __init__(self, testparams: KModuleParams, consumers):
        self.params = testparams
        self.consumers = consumers
        self.ignored_fields = []

    # Deploys the traffic reproduction container with the provided name. The container needs to have
    # been defined and named accordingly in file container-setup.yml, which means the relevant folder
    # will have been created under the test results folder.
    def spawn_traffic_container(self, container_name: str, detached: bool = False) -> bool:
        logger.debug('Traffic folders: ' + str(self.params.traffic_folders))
        pcap_folder = self.params.traffic_folders.get_path_like(container_name)
        return scripts.replay_pcap(pcap_folder, detached)

    # Undeploys and deletes the traffic reproduction container with the provided name.
    def delete_traffic_container(self, container_name: str) -> bool:
        pcap_folder = self.params.traffic_folders.get_path_like(container_name)
        return scripts.stop_and_remove_traffic_container(pcap_folder)

    # Sets the top-level json fields that will be ignored when comparing messages at json level
    def set_ignored_fields(self, ignored_fields):
        self.ignored_fields = ignored_fields

    # Consumes from the provided kafka topic topic_name as many messages as the number of lines in the json
    # reference file implied by the keyword reference_json (searched for with *like* in the tests folder). Then,
    # it compares the received messages with the jsons corresponding to the lines in the reference file.
    # If OVERWRITE=true environment variable is set, the output test files are overwritten (used for test development)
    def read_and_compare_messages(self, topic_name: str, reference_json: str, wait_time: int = 120) -> bool:
        consumer = self.consumers.get_consumer_of_topic_like(topic_name)

        if self.params.overwrite_json_output:
            return test_tools.read_messages_and_overwrite_output_files(consumer, self.params, reference_json,
                                                                       wait_time) 
        else:
            return test_tools.read_and_compare_messages(consumer, self.params, reference_json,
                                                        self.ignored_fields, wait_time)

    # Identifies the reference log file corresponding to log_tag and transforms it with respect to
    # traffic reproduction IP address and other wildcards/regexes used therein. The traffic reproduction
    # IP is figured out from the yml file of the container, whose name is passed as parameter.
    def transform_log_file(self, log_tag: str, name: str = None):
        logfile = self.params.log_files.get_path_like(log_tag)
        repro_ip = None
        if name:
            repro_ip = helpers.get_reproduction_ip(self.params.traffic_folders.get_path_like(name) +
                                                   '/pcap0/traffic-reproducer.yml')
        test_tools.transform_log_file(logfile, repro_ip)

    # Identifies the reference log file corresponding to log_tag and transforms it with respect to
    # traffic reproduction IP address and other wildcards/regexes used therein. The traffic reproduction
    # IP is given as a parameter.
    def transform_log_file_with_ip(self, log_tag: str, ip: str):
        logfile = self.params.log_files.get_path_like(log_tag)
        test_tools.transform_log_file(logfile, ip)

    # Identifies the reference log file corresponding to log_tag and uses the regular expressions therein
    # (one in each line) to check the content of the actual log file of the pmacct instance of name pmacct_name.
    # If no pmacct_name is passed, the first one having been deployed is used.
    def check_file_regex_sequence_in_pmacct_log(self, log_tag: str, pmacct_name: str = None) -> bool:
        logfile = self.params.log_files.get_path_like(log_tag)
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.check_file_regex_sequence_in_file(pmacct.pmacct_log_file, logfile)

    # Checks the content of the log file of the pmacct instance of name pmacct_name against a list of regular
    # expressions included in the file implied by log_tag (searched for with *like* in the test results folder).
    # If no pmacct_name is passed, the first one having been deployed is used. If there is no match, the
    # checking is repeated after <seconds_repeat> seconds for a maximum time of <max_seconds> seconds.
    def wait_and_check_logs(self, log_tag: str, max_seconds: int, seconds_repeat: int, pmacct_name: str = None) -> bool:
        logfile = self.params.log_files.get_path_like(log_tag)
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.retry_until_true('Checking expected logs',
                                        lambda: helpers.check_file_regex_sequence_in_file(pmacct.pmacct_log_file,
                                                                                          logfile),
                                        max_seconds, seconds_repeat)

    # Checks the content of the log file of the pmacct instance of name pmacct_name against a single regular
    # expressions provided in the regexes parameter. If no pmacct_name is passed, the first one having been
    # deployed is used.
    def check_regex_in_pmacct_log(self, regex: str, pmacct_name: str = None) -> bool:
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.check_regex_sequence_in_file(pmacct.pmacct_log_file, [regex])

    # TODO: document here...
    def wait_and_check_regex_in_pmacct_log(self, regex: str, max_seconds: int, seconds_repeat: int, pmacct_name: str = None) -> bool:
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.retry_until_true('Checking expected logs',
                                        lambda: helpers.check_regex_sequence_in_file(pmacct.pmacct_log_file, [regex]),
                                        max_seconds, seconds_repeat)


    # Checks the content of the log file of the pmacct instance of name pmacct_name against a list of regular
    # expressions provided in the regexes parameter. If no pmacct_name is passed, the first one having been
    # deployed is used.
    def check_regex_sequence_in_pmacct_log(self, regexes: List, pmacct_name: str = None) -> bool:
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.check_regex_sequence_in_file(pmacct.pmacct_log_file, regexes)

    # TODO: document here...
    def wait_and_check_regex_sequence_in_pmacct_log(self, regexes: List, max_seconds: int, seconds_repeat: int, pmacct_name: str = None) -> bool:
        pmacct = self.params.get_pmacct_with_name(pmacct_name) if pmacct_name else self.params.pmacct[0]
        return helpers.retry_until_true('Checking expected logs',
                                        lambda: helpers.check_regex_sequence_in_file(pmacct.pmacct_log_file, regexes),
                                        max_seconds, seconds_repeat)

    # Disconnects all consumers from the kafka infrastructure
    def disconnect_consumers(self):
        for c in self.consumers:
            c.disconnect()

    # Sends signal <sig> (e.g., SIGUSR1) to the pmacct instance with name pmacct_name
    def send_signal_to_pmacct(self, sig: str, pmacct_name: str = None) -> bool:
        if not pmacct_name:
            pmacct_name = self.params.pmacct[0].name
        return scripts.send_signal_to_pmacct(pmacct_name, sig)
