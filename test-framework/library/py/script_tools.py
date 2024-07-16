###################################################
# Automated Testing Framework for Network Analytics
# Functions for calling shell scripts and returning
# the outcome
# nikolaos.tsokas@swisscom.com 26/02/2023
###################################################

import subprocess
import time
import logging
from typing import List, Callable, Tuple
logger = logging.getLogger(__name__)


# Runs the command and returns a tuple of its result (success or not) and the message output
# command: a list of strings, first of which is the called script, the rest being the arguments
def run_script(command: List[str]) -> (bool, str, str):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8').strip()
        error = result.stderr.decode('utf-8').strip()
        success = result.returncode == 0
    except Exception as e:
        output = 'Exception thrown' + str(e)
        error = ''
        success = False
    if not success:
        logger.debug('Success: ' + str(success))
        if len(output) > 0:
            logger.debug('Output: ' + output)
        if len(error) > 0:
            logger.debug('Error: ' + error)
    return success, output, error


# Runs a script, which waits for a container to reach a certain state, for a maximum of time
# If the maximum time is reached without the state having been reached, it returns False. Otherwise, True.
# command: a list of strings, first of which is the called script, the rest being the arguments
# name: the name of the container
# checkfunc: the function that checks whether the desired state has been reached. It takes as input a
#    tuple of the form (bool, str) and returns True or False, in terms of the state having been reached or not
def wait_for_container(command: str, name: str, checkfunc: Callable[[Tuple[bool, str]], bool], seconds: int,
                       sec_update: int = 1) -> bool:
    logger.info('Waiting for ' + name + ' to be functional')
    out = run_script([command, name])
    while not checkfunc(out):
        seconds -= 1
        if seconds < 0:
            logger.info(name + ' check timed out')
            return False
        time.sleep(1)
        if seconds % sec_update == 0:
            logger.debug('Still waiting for ' + name + '...')
        out = run_script([command, name])
    logger.info(name + ' is up and running')
    return True
