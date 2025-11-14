###################################################
# Automated Testing Framework for Network Analytics
# Functions for repeatable/common functionality
# nikolaos.tsokas@swisscom.com 07/07/2023
###################################################

import logging
import secrets
import time
import datetime
import shutil
import library.py.json_tools as jsontools
import library.py.helpers as helpers
import library.py.escape_regex as escape_regex
from library.py.kafka_consumer import KMessageReader
from library.py.test_params import KModuleParams
from typing import List
logger = logging.getLogger(__name__)

def replace_ips_and_get_reference_file(params: KModuleParams, json_name: str):
    # Replacing IP addresses in output json file with the ones anticipated from pmacct
    output_json_file = params.output_files.get_path_like(json_name)
    helpers.replace_ips(params, output_json_file)
    logger.info('Using reference file ' + helpers.short_name(output_json_file))
    return output_json_file


# Reads messages from Kafka topic and compares with given file. First argument is the Kafka consumer object,
# which will be used for reading. The number of messages anticipated is equal to the number of non-empty
# lines of the json file passed as second argument. The latter is first edited in terms of referenced IPs,
# as per the ip_subst_pairs, which are pairs of IPs, representing which IPs must be replaced by which.
def read_and_compare_messages(consumer: KMessageReader, params: KModuleParams, json_name: str,
                              ignore_fields: List, wait_time: int = 120) -> bool:
    output_json_file = replace_ips_and_get_reference_file(params, json_name)
    # Counting non-empty json lines in output file, so that we know the number of anticipated messages
    line_count = helpers.count_non_empty_lines(output_json_file)
    logger.info('Expecting ' + str(line_count) + ' messages')

    # Reading messages from Kafka topic
    # Max wait time for line_count messages is 120 seconds by default (overriden in arguments)
    # The get_messages method will return only if either line_count messages are received,
    # or 120 seconds have passed
    messages = consumer.get_messages(wait_time, line_count)
    if len(messages) < 1:
        logger.warning('No messages read by kafka consumer in ' + str(wait_time) + ' second(s)')
        return False
    elif len(messages) < line_count:
        logger.warning('Received ' + str(len(messages)) + ' messages instead of ' + str(line_count) + ' in ' + str(wait_time) + ' second(s)')
        return False
    elif line_count == len(messages):
        logger.info('Received the expected number of messages (' + str(len(messages)) + ')')
    else:
        logger.error('Received more messages than expected')
        return False

    # Comparing the received messages with the anticipated ones
    # output_json_file is a file (filename) with json lines
    logger.info('Comparing messages received with json lines in file ' + helpers.short_name(output_json_file))
    return jsontools.compare_messages_to_json_file(messages, output_json_file, ignore_fields)


# Reads all messages from Kafka topic within a specified timeout (wait_time)
# --> used for test-case development
def read_messages_dump_only(consumer: KMessageReader, params: KModuleParams, wait_time: int = 120) -> bool:
    logger.info('Consuming from kafka [timeout=' + str(wait_time) + 's] and dumping messages in ' +
                params.results_dump_folder)

    # Reading messages from Kafka topic
    # The get_messages method with wait_time as only argument consumes all messages and returns 
    # when wait_time (default=120s) has passed
    messages = consumer.get_messages(wait_time)
    if len(messages) < 1:
        logger.warning('No messages read by kafka consumer in ' + str(wait_time) + ' second(s)')
        return False

    logger.info('Consumed ' + str(len(messages)) + ' messages')
    logger.warning('Json comparing disabled (test-case development)!')
    return True 


# Reads all messages from Kafka topic within a specified timeout (wait_time)
# and overwrites the relative output json file (used for test-case development)
# While doing so, it also:
# - removes (pmacct internal) timestamp fields from the output json file
# - aligns columns in the output json file
def read_messages_and_overwrite_output_files(consumer: KMessageReader, params: KModuleParams, json_name: str,
                                             wait_time: int = 120) -> bool:

    logger.info('Consuming from kafka [timeout=' + str(wait_time) + 's]')
    messages = consumer.get_messages(wait_time)
    if len(messages) < 1:
        logger.warning('No messages read by kafka consumer in ' + str(wait_time) + ' second(s)')
        return False

    logger.info('Consumed ' + str(len(messages)) + ' messages')

    kafka_dump_file = consumer.dumpfile + '.json'
    output_json_file = helpers.KPathList(params.test_output_files).get_path_like(json_name)
    with open(kafka_dump_file, 'r') as kafka_dump:
        content = kafka_dump.read()
    with open(output_json_file, 'w') as output_json:
        output_json.write(content)

    # Remove (pmacct internal) timestamp fields from the output json file
    fields_to_remove = ['timestamp_arrival', 'timestamp_min', 'timestamp_max', 'stamp_inserted', 'stamp_updated']
    jsontools.remove_fields_from_json(output_json_file, fields_to_remove)

    logger.warning('OVERWRITE=true - file changed: ' + output_json_file)

    # Move the kafka_dump_file to a new file with a timestamp
    # (to support consuming multiple times from the same topic)
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    new_kafka_dump_file = consumer.dumpfile + '_' + timestamp + '.json'
    shutil.move(kafka_dump_file, new_kafka_dump_file)
    logger.info('Moved kafka dump file to: ' + new_kafka_dump_file)

    return True 


# Transforms a provided log file, in terms of regex syntax and IP substitutions
# repro_ip can be a regular expression
def transform_log_file(filename: str, repro_ip: str = None):
    token_ip = None
    if repro_ip and helpers.file_contains_string(filename, '${repro_ip}'):
        token_ip = secrets.token_hex(4)[:8]
        helpers.replace_in_file(filename, '${repro_ip}', token_ip)
    token1 = secrets.token_hex(4)[:8]
    if helpers.file_contains_string(filename, '${TIMESTAMP}'):
        helpers.replace_in_file(filename, '${TIMESTAMP}', token1)
    if helpers.file_contains_string(filename, '${IGNORE_REST}'):
        helpers.replace_in_file(filename, '${IGNORE_REST}', '')
    token2 = secrets.token_hex(4)[:8]
    if helpers.file_contains_string(filename, '${RANDOM}'):
        helpers.replace_in_file(filename, '${RANDOM}', token2)
    escape_regex.escape_file(filename)
    if helpers.file_contains_string(filename, token1):
        helpers.replace_in_file(filename, token1, '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}[+-]\\d{2}:\\d{2}')
    if helpers.file_contains_string(filename, token2):
        helpers.replace_in_file(filename, token2, '.+')
    if token_ip:
        helpers.replace_in_file(filename, token_ip, repro_ip)


# Checks current second and, if needed, waits until the sleep period ends.
# Example: a process should not start before hh:mm:15 (=end_of_period) and it might take up to 30 seconds (=length).
# --> avoid_time_period_in_seconds(15, 30) will sleep when time is greater than mm:45 or smaller than mm:15, 
#     and exits when time arrives at (or is already bigger than) mm:15.
def avoid_time_period_in_seconds(end_of_period: int, length: int):
    if length > 60:
        raise Exception('Avoided time period longer than 1 minute (must be <= 60sec)')

    curr_sec = datetime.datetime.now().second
    logger.info('Current minute seconds: ' + str(curr_sec))

    start_of_period = end_of_period - length
    if start_of_period >= 0:
        if start_of_period <= curr_sec < end_of_period:
            wait_sec = end_of_period - curr_sec
        else:
            wait_sec = 0
    else:
        start_of_period += 60
        if curr_sec < end_of_period:
            wait_sec = end_of_period - curr_sec
        elif curr_sec > start_of_period:
            wait_sec = 60 - curr_sec + end_of_period
        else:
            wait_sec = 0

    if wait_sec < 1:
        logger.debug('No need to wait')
    else:
        logger.debug('Waiting ' + str(wait_sec) + ' seconds')
        time.sleep(wait_sec)


# Waits until the next occurrence of second, i.e., until the time gets hh:mm:second. If current time happens
# to be equal to hh:mm:second, no wait time is applied and the function returns immediately
def wait_until_second(second: int):
    avoid_time_period_in_seconds(second, 60)
