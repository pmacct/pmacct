###################################################
# Automated Testing Framework for Network Analytics
# json tools commonly used by framework functions
# nikolaos.tsokas@swisscom.com 26/02/2023
###################################################

import logging
import json
from typing import List, Dict, Union, Optional
logger = logging.getLogger(__name__)


# Compares json messages received (json1) with json lines expected (json2)
def compare_json_objects(json1: Union[List, Dict], json2: Union[List, Dict]) -> Optional[Union[List, Dict]]:
    if isinstance(json1, dict) and isinstance(json2, dict):
        keys1 = set(json1.keys())
        keys2 = set(json2.keys())
        common_keys = keys1.intersection(keys2)
        added_keys = keys2 - keys1
        removed_keys = keys1 - keys2
        differences = {}
        for key in common_keys:
            nested_diff = compare_json_objects(json1[key], json2[key])
            if nested_diff:
                differences[key] = nested_diff
        for key in added_keys:
            differences[key] = {'missing': json2[key]}
        for key in removed_keys:
            differences[key] = {'got unknown': json1[key]}
        return differences if differences else None
    elif isinstance(json1, list) and isinstance(json2, list):
        if len(json1) != len(json2):
            return {'length': {'got': len(json1), 'expected': len(json2)}}
        differences = []
        for i in range(len(json1)):
            nested_diff = compare_json_objects(json1[i], json2[i])
            if nested_diff:
                differences.append(nested_diff)
        return differences if differences else None
    else:
        if json1 != json2:
            return {'value': {'received': json1, 'expected': json2}}
        return None


# Compares two json objects, which have been deprived of potentially irrelevant fields (to be ignored)
def compare_json_ignore(json1: Dict, json2: Dict, ignore_fields: List[str] = None):
    if ignore_fields:
        for field in ignore_fields:
            json1.pop(field, None)
            json2.pop(field, None)
    return compare_json_objects(json1, json2)


# Removes first item from json_list1 and matches it to the items of json_list2 (optionally ignoring some top-level
# json fields). Returns the index of the matched element of json_list2 or -1 if matching failed. If matching fails,
# it logs the "closest" (partial) match and the difference to the popped item (i.e., first item of json_list1).
def pop_and_match_first_item(json_list1: List[Dict], json_list2: List[Dict], ignore_fields: List[str]) -> int:
    json1 = json_list1.pop(0)
    logger.debug('Matching: ' + str(json1))
    index = 0
    min_diff, min_diff_len, min_diff_index = -1, 1000000000, -1
    json2 = json_list2[index]
    diff = compare_json_ignore(json1, json2, ignore_fields)
    while diff:
        if len(diff) < min_diff_len:
            min_diff, min_diff_len, min_diff_index = diff, len(diff), index
        index += 1
        if index >= len(json_list2):
            logger.info('Received message not matched: ' + str(json1))
            logger.info('Closest match: ' + str(json_list2[min_diff_index]))
            logger.info('Closest match delta: ' + str(min_diff))
            return -1
        json2 = json_list2[index]
        diff = compare_json_ignore(json1, json2, ignore_fields)
    logger.debug('Json matched')
    return index


# This function performs a 1-to-1 match across json_list1 and json_list2. That means all items of json_list1 need
# to match exactly one item of json_list2 and vice versa. It optionally ignores some top-level json fields.
# Every json object of the first list (json_list1) is checked against the full json_list2. If there's
# match, regardless of the order, the lines are considered as matching. The comparison fails at the first
# occurrence of a line in json_list1 not matching any object in json_list2.
# The matched element of json_list2 is every time removed, too.
def compare_json_lists(json_list1: List[str], json_list2: List[str], ignore_fields: List[str] = None) -> bool:
    json_list1 = [json.loads(x.strip()) for x in json_list1 if len(x) > 3]
    json_list2 = [json.loads(x.strip()) for x in json_list2 if len(x) > 3]
    logger.info('Comparing json lists (lengths: ' + str(len(json_list1)) + ', ' + str(len(json_list2)) + ')')
    if len(json_list1) != len(json_list2):
        logger.info('Json lists have different sizes')
        return False
    while len(json_list1):
        index = pop_and_match_first_item(json_list1, json_list2, ignore_fields)
        if index < 0:
            return False
        json_list2.pop(index)
    logger.info('All json matched')
    return True


# This function performs a many-to-1 match across json_list1 and json_list2. That means each item of json_list1
# needs to match an item of json_list2, but each of json_list2 can be matched multiple times (as many as max_matches).
# Each item in json_list2 needs to be matched by at least one item of json_list1. The function maintains match
# counters for each item of json_list2 (i.e., how many times an item of json_list2 has been matched).
# It optionally ignores some top-level json fields.
def compare_json_lists_multi_match(json_list1: List[str], json_list2: List[str],
                                   ignore_fields: List[str] = None, max_matches: int = -1) -> bool:
    json_list1_len = len(json_list1)
    json_list1 = [json.loads(x.strip()) for x in json_list1 if len(x) > 3]
    json_list2 = [json.loads(x.strip()) for x in json_list2 if len(x) > 3]
    json_list2_occurrences = [0] * len(json_list2)
    logger.info('Comparing json lists (lengths: ' + str(len(json_list1)) + ', ' + str(len(json_list2)) + ')')
    while len(json_list1):
        index = pop_and_match_first_item(json_list1, json_list2, ignore_fields)
        if index < 0:
            return False
        json_list2_occurrences[index] = json_list2_occurrences[index] + 1
        if -1 < max_matches < json_list2_occurrences[index]:
            logger.info('Json file line was matched more times than allowed (' +
                        str(json_list2_occurrences[index]) +
                        ' instead of ' + str(max_matches) + ')')
            return False
    logger.info('All ' + str(json_list1_len) + ' received messages matched to reference json file lines')
    occs = [str(x) + ' time(s) - ' + str(json_list2_occurrences.count(x)) + ' lines'
            for x in set(json_list2_occurrences)]
    logger.debug('Reference json line occurrences: ' + str(occs))
    dst_unmatched = 0
    for i in range(len(json_list2_occurrences)):
        if json_list2_occurrences[i] < 1:
            dst_unmatched += 1
            logger.debug('Reference json file line not matched: ' + str(json_list2[i]))
    if dst_unmatched > 0:
        logger.info(str(dst_unmatched) + ' reference json file lines were not matched to any received message')
        return False
    logger.info('All ' + str(len(json_list2)) + ' reference json file lines matched to received messages')
    return True


# Compares a list of dictionaries, which correspond to the messages received from Kafka, with the lines of a
# reference file, which depict json structures. Optionally it ignores a set of top-level json fields (ignore_fields).
# If multi_match_allowed is set to False (default value), all incoming messages (message_dicts) must match exactly
# one line of the json reference file (jsonFile) and vice versa.
# If multi_match_allowed is set to True, every reference json line can potentially be matched by multiple incoming
# Kafka messages. This is useful in case e.g. we are expecting message duplicates from multiple pmacct instances.
def compare_messages_to_json_file(message_dicts: List[Dict], jsonfile: str, ignore_fields: List[str] = None,
                                  multi_match_allowed: bool = False, max_matches: int = -1) -> bool:
    with open(jsonfile) as f:
        lines = f.readlines()
    jsons = [json.dumps(msg) for msg in message_dicts]
    if multi_match_allowed:
        return compare_json_lists_multi_match(jsons, lines, ignore_fields, max_matches)
    return compare_json_lists(jsons, lines, ignore_fields)

# Removes fields from a json object
def remove_fields_from_json(input_file, fields_to_remove):
    logger.info(f'Removing fields "{fields_to_remove}" from JSON message')

    with open(input_file, 'r') as infile:
        content = infile.readlines()

    modified_content = []
    for line in content:
        json_message = json.loads(line)
        for field in fields_to_remove:
            if field in json_message:
                del json_message[field]
        modified_content.append(json.dumps(json_message))

    with open(input_file, 'w') as outfile:
        outfile.write('\n'.join(modified_content))

# Aligns json columns for better visualization (used for development/debugging only)
def align_json_columns(input_file):
    logger.info(f'Aligning json columns for better visualization')

    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    json_objects = [json.loads(line) for line in lines]
    
    all_keys = sorted(set(key for obj in json_objects for key in obj.keys()))

    max_key_length = max(len(key) for key in all_keys)
    max_value_lengths = {key: max(len(json.dumps(obj.get(key, ''))) for obj in json_objects) for key in all_keys}

    formatted_lines = []
    for obj in json_objects:
        formatted_line = '{'
        for key in all_keys:
            value = json.dumps(obj.get(key, ''))
            formatted_line += f'"{key}": {value.ljust(max_value_lengths[key])}, '
        formatted_line = formatted_line.rstrip(', ') + '}'
        formatted_lines.append(formatted_line)

    with open(input_file, 'w') as outfile:
        outfile.write('\n'.join(formatted_lines))
