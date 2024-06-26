###################################################
# Automated Testing Framework for Network Analytics
# Class encapsulating a pmacct configuration file
# nikolaos.tsokas@swisscom.com 16/05/2023
###################################################

import re
import logging
from typing import List, Dict
logger = logging.getLogger(__name__)


# Represents a pmacct configuration file. The --> syntax key[subkey]: value <-- is assumed.
class KConfigurationFile:
    def __init__(self, filename: str):
        self.data = {}
        self.read_conf_file(filename)

    # Loads pmacct configuration from file whose name is passed
    def read_conf_file(self, filename: str):
        self.data = {}
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if '#' in line:
                    line = line.split('#')[0].strip()
                if '!' in line:
                    line = line.split('!')[0].strip()
                if len(line) < 1:
                    continue
                if ':' in line:
                    key_value = line.split(':', 1)
                    key = key_value[0].strip()
                    value = key_value[1].strip()
                    match = re.match(r'^([^\[]+)\[([^]]+)]', key)
                    if match:
                        main_key = match.group(1)
                        sub_key = match.group(2)
                    else:
                        main_key = key
                        sub_key = ''
                    if main_key not in self.data:
                        self.data[main_key] = {}
                    self.data[main_key][sub_key] = value

    # Replaces in memory the value of a key. If key has subkey (e.g.. thekey[thesubkey]: thevalue), then
    # the subkey can also be provided. If subkey argument is None, all subkey values will be replaced. If
    # key is not found, False is returned. If subkey is not None and is not found, True is returned.
    def replace_value_of_key(self, key: str, value: str, subkey: str = None) -> bool:
        if key not in self.data:
            return False
        if len(self.data[key]) < 1:
            return False
        for sk in self.data[key]:
            if subkey is None or sk == subkey:
                self.data[key][sk] = value
        return True

    # Replaces in memory the values of all keys ending with "key_ending". For example,
    # replace_value_of_key_ending_with('_tag_map', 'map_filename') will replace the values of all
    # keys ending with _tag_map with value "map_filename". If subkey is provided, only matched subkeys
    # are changed. Otherwise, all subkeys are affected.
    def replace_value_of_key_ending_with(self, key_ending: str, value: str, subkey: str = None):
        for key in self.data.keys():
            if key.endswith(key_ending):
                for sk in self.data[key]:
                    if subkey is None or sk == subkey:
                        self.data[key][sk] = value

    # Returns all kafka topics found in the configration file. Different Kafka topics need to have
    # different keys!
    def get_kafka_topics(self) -> Dict:
        retval = {}
        for propname in self.data.keys():
            if propname.endswith('kafka_topic'):
                if len(self.data[propname].keys()) > 1:
                    raise Exception('Encountered two kafka topics with same key and different subkeys')
                retval[propname] = list(self.data[propname].values())[0]
        return retval

    # Used when dumping configuration back to file. Follows syntax: --> key[subkey]: value <--
    def print_key_to_stringlist(self, key: str) -> List[str]:
        lines = []
        for k in self.data[key]:
            if k == '':
                lines.append(key + ': ' + self.data[key][k])
            else:
                lines.append(key + '[' + k + ']: ' + self.data[key][k])
        return lines

    # Dumps configuration back to a file
    def print_to_file(self, filename: str):
        logger.debug('Dumping configuration to file: ' + filename)
        with open(filename, 'w') as f:
            for key in self.data:
                lines = self.print_key_to_stringlist(key)
                for line in lines:
                    f.write(line + '\n')
