###################################################
# Automated Testing Framework for Network Analytics
# Functions for preparing the environment for the
# test case to run in - pmacct part
# nikolaos.tsokas@swisscom.com 11/05/2023
###################################################

import shutil
import secrets
import logging
import os
import yaml
from library.py.configuration_file import KConfigurationFile
from library.py.test_params import KPmacctParams, KModuleParams
from typing import List
from library.py.helpers import short_name, select_files, replace_ips, KPathList
logger = logging.getLogger(__name__)


# Creates the docker-compose file for deploying pmacct.
def create_pmacct_compose_files(params: KModuleParams):
    pmacct_index = 0
    for pmacct in params.pmacct:
        img_var_name = 'PMACCT_' + pmacct.daemon.upper() + '_IMG'
        pmacct_img = params.fw_config.get(img_var_name)
        pmacct_index += 1
        with open(params.root_folder + '/library/sh/pmacct_docker/docker-compose-template.yml') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
        data['services']['pmacct']['image'] = pmacct_img
        data['services']['pmacct']['container_name'] = pmacct.name
        vols = data['services']['pmacct']['volumes']
        for i in range(len(vols)):
            vols[i] = vols[i].replace('${PMACCT_CONF}', pmacct.results_conf_file)
            vols[i] = vols[i].replace('${PMACCT_DAEMON}', params.daemon)
            vols[i] = vols[i].replace('${PMACCT_MOUNT}', pmacct.results_mount_folder)
        data['services']['pmacct']['networks']['pmacct_test_network']['ipv4_address'] = pmacct.ipv4
        data['services']['pmacct']['networks']['pmacct_test_network']['ipv6_address'] = pmacct.ipv6
        with open(pmacct.docker_compose_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Creates mount and output subfolders in the test results folder
def create_mount_and_output_folders(params: KPmacctParams):
    logger.info('Creating test mount folder: ' + short_name(params.results_mount_folder))
    os.makedirs(params.results_mount_folder)
    logger.info('Creating test output folder: ' + short_name(params.results_output_folder))
    _mask = os.umask(0)
    os.makedirs(params.results_output_folder, 0o777)
    os.umask(_mask)
    logger.debug('Mount and output folders created')


# Files in mounted folder, for pmacct to read
def edit_conf_mount_folder(config: KConfigurationFile, params: KModuleParams):
    config.replace_value_of_key('flow_to_rd_map', params.pmacct_mount_folder + '/f2rd-00.map')
    config.replace_value_of_key('sampling_map', params.pmacct_mount_folder + '/sampling-00.map')
    config.replace_value_of_key('aggregate_primitives', params.pmacct_mount_folder + '/custom-primitives-00.map')
    config.replace_value_of_key_ending_with('_tag_map', params.pmacct_mount_folder + '/pretag-00.map')
    config.replace_value_of_key_ending_with('kafka_config_file', params.pmacct_mount_folder + '/librdkafka.conf')


# Files in output folder, for pmacct to write
def edit_conf_output_folder(config: KConfigurationFile, params: KModuleParams):
    config.replace_value_of_key('logfile', params.pmacct_output_folder + '/pmacctd.log')
    config.replace_value_of_key('pidfile', params.pmacct_output_folder + '/pmacctd.pid')
    config.replace_value_of_key('bgp_neighbors_file', params.pmacct_output_folder + '/nfacctd_bgp_neighbors.lst')
    config.replace_value_of_key_ending_with('avro_schema_file',
                                            params.pmacct_output_folder + '/avsc/nfacctd_msglog_avroschema.avsc')
    config.replace_value_of_key_ending_with('avro_schema_output_file',
                                            params.pmacct_output_folder + '/avsc/nfacctd_msglog_avroschema.avsc')


# Calls above two functions; also, sets the correct schema registry URL and the correct address:port of redis
def edit_config_with_framework_params(config: KConfigurationFile, params: KModuleParams):
    edit_conf_mount_folder(config, params)
    edit_conf_output_folder(config, params)
    config.replace_value_of_key_ending_with('kafka_avro_schema_registry', 'http://schema-registry:8081')
    config.replace_value_of_key('redis_host', '172.21.1.14:6379')


# Copy existing files in pmacct_mount to result (=actual) mounted folder
def copy_files_in_mount_folder(test_mount_folder: str, results_mount_folder: str):
    if os.path.exists(test_mount_folder):
        src_files = os.listdir(test_mount_folder)
        count = 0
        for file_name in src_files:
            full_file_name = os.path.join(test_mount_folder, file_name)
            if os.path.isfile(full_file_name) and not file_name.startswith('.'):
                count += 1
                logger.debug('Copying: ' + short_name(full_file_name))
                shutil.copy(full_file_name, results_mount_folder)
        logger.info('Copied ' + str(count) + ' files')


# RUNS BEFORE PMACCT IS RUN
# Prepares results folder to receive logs and output from pmacct
def prepare_test_env(params: KModuleParams, scenario: str):
    params.build_dynamic_params(scenario)

    if os.path.exists(params.results_folder):
        logger.debug('Results folder exists, deleting folder ' + short_name(params.results_folder))
        shutil.rmtree(params.results_folder)
        assert not os.path.exists(params.results_folder)

    params.kafka_topics = {}
    for pmacct in params.pmacct:
        config = KConfigurationFile(pmacct.test_conf_file)
        pmacct.process_name = config.data['core_proc_name']['']
        topicsdict = config.get_kafka_topics()
        for k in topicsdict.keys():
            if topicsdict[k] not in params.kafka_topics.keys():
                params.kafka_topics[topicsdict[k]] = topicsdict[k] + '.' + secrets.token_hex(4)[:8]
            config.replace_value_of_key(k, params.kafka_topics[topicsdict[k]])
        logger.debug('Kafka topic(s): ' + str(params.kafka_topics))

        create_mount_and_output_folders(pmacct)
        edit_config_with_framework_params(config, params)
        config.print_to_file(pmacct.results_conf_file)

        copy_files_in_mount_folder(params.test_mount_folder, pmacct.results_mount_folder)
        if scenario != 'default':  # copy scenario-specific map files to results mount folder
            for map_file in select_files(params.test_folder + '/' + scenario, '.+\\.map$'):
                shutil.copy(map_file, params.results_mount_folder)
        for results_pretag_file in select_files(pmacct.results_mount_folder, '.+\\.map$'):
            replace_ips(params, results_pretag_file)
        shutil.copy(params.root_folder + '/library/librdkafka.conf', pmacct.results_mount_folder)

    def copy_list(filelist: List) -> List[str]:
        retval = KPathList()
        for src_filepath in filelist:
            dst_filepath = params.results_folder + '/' + os.path.basename(src_filepath)
            retval.append(dst_filepath)
            shutil.copy(src_filepath, dst_filepath)
        return retval
    params.output_files = copy_list(params.test_output_files)
    params.log_files = copy_list(params.test_log_files)
