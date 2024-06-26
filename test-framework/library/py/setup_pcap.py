###################################################
# Automated Testing Framework for Network Analytics
# Functions for preparing the environment for the
# test case to run in - traffic reproduction part
# nikolaos.tsokas@swisscom.com 11/05/2023
###################################################

import shutil
import logging
import os
import yaml
from library.py.test_params import KModuleParams
import library.py.helpers as helpers
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class KTrafficSetup:

    def __init__(self, params: KModuleParams):
        self.params = params

    # All functionality triggered by this method, which is the only "public"
    def build(self):
        self.params.traffic_folders.clear()
        if not os.path.isfile(self.params.test_folder + '/container-setup.yml'):
            logger.info('No container-setup.yml file detected, no traffic reproduction set up')
            return
        with open(self.params.test_folder + '/container-setup.yml') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
        for container in data['containers']:
            self._setup_container_files(container)

    def _setup_container_files(self, container: Dict):
        folder_name = self.params.results_folder + '/' + container['name']
        os.makedirs(folder_name)
        self.params.traffic_folders.append(folder_name)

        repro_ip = self._get_reproduction_ip_of_container(container)
        if not repro_ip:
            raise Exception('No or multiple IP addresses referenced for container ' + container['name'])
        is_ipv6 = ':' in repro_ip

        self._build_container_docker_compose(folder_name, container['name'], repro_ip, is_ipv6)

        for i in range(len(container['processes'])):
            process_folder = folder_name + '/pcap' + str(i)
            self._setup_process_files(folder_name, container['processes'][i], process_folder, is_ipv6)

    def _build_container_docker_compose(self, folder_name: str, container_name: str, reproduction_ip: str,
                                        is_ipv6: bool):
        # Build docker-compose.yml for the traffic container and dump it to the container folder
        with open(self.params.root_folder + '/library/sh/traffic_docker/docker-compose-template.yml') as f:
            data_dc = yaml.load(f, Loader=yaml.FullLoader)
        data_dc['services']['traffic-reproducer']['container_name'] = container_name
        data_dc['services']['traffic-reproducer']['image'] = self.params.fw_config.get('TRAFFIC_REPRO_IMG')
        data_dc['services']['traffic-reproducer']['volumes'][0] = folder_name + ':/pcap'
        ex_subnet, fw_subnet = self._get_external_and_framework_subnets(is_ipv6)
        keep_addr_type = 'ipv6_address' if is_ipv6 else 'ipv4_address'
        del_addr_type = 'ipv4_address' if is_ipv6 else 'ipv6_address'
        ip_value = reproduction_ip if len(ex_subnet) < 1 else reproduction_ip.replace(ex_subnet, fw_subnet)
        data_dc['services']['traffic-reproducer']['networks']['pmacct_test_network'][keep_addr_type] = ip_value
        del data_dc['services']['traffic-reproducer']['networks']['pmacct_test_network'][del_addr_type]
        with open(folder_name + '/docker-compose.yml', 'w') as f:
            yaml.dump(data_dc, f, default_flow_style=False, sort_keys=False)

    def _get_external_and_framework_subnets(self, is_ipv6: bool) -> Tuple[str, str]:
        ex_subnet = self.params.test_subnet_ipv6 if is_ipv6 else self.params.test_subnet_ipv4
        fw_subnet = 'fd25::10' if is_ipv6 else '172.21.1.10'
        return ex_subnet, fw_subnet

    def _get_reproduction_ip_of_container(self, container: Dict) -> Optional[str]:
        # Make sure traffic-reproducer.yml files of all pcap folders refer to the same IP and BGP_ID
        # Otherwise, it is not possible for a single server (container) to replay these traffic data
        config_file_src = self.params.test_folder + '/' + container['processes'][0]['config']
        repro_ip = helpers.get_reproduction_ip(config_file_src)
        for i in range(1, len(container['processes'])):
            config_file_src = self.params.test_folder + '/' + container['processes'][i]['config']
            if repro_ip != helpers.get_reproduction_ip(config_file_src):
                logger.error('IP addresses assigned to the same traffic reproducer do not match!')
                return None
        return repro_ip

    def _fix_repro_ip_in_config(self, config: Dict, is_ipv6: bool):
        ex_subnet, fw_subnet = self._get_external_and_framework_subnets(is_ipv6)
        if len(ex_subnet) < 1:
            logger.info('Reference subnet not set, assuming traffic reproduction IP from framework subnet')
        else:
            logger.info('Reference subnet set, setting traffic reproduction IP to framework subnet')
            config['network']['map'][0]['repro_ip'] = config['network']['map'][0]['repro_ip'].replace(ex_subnet,
                                                                                                      fw_subnet)

    def _build_process_traffic_yml(self, traffic_yml_file: str, pcap_file: str, collector_name: str, is_ipv6: bool):
        with open(traffic_yml_file) as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
        data['pcap'] = '/pcap/' + pcap_file
        pmacct = self.params.get_pmacct_with_name(collector_name)
        pmacct_ip = pmacct.ipv6 if is_ipv6 else pmacct.ipv4
        logger.debug('Traffic reproducer uses ' + ('IPv6' if is_ipv6 else 'IPv4'))
        for k in ['bmp', 'bgp', 'ipfix']:
            if k in data:
                data[k]['collector']['ip'] = pmacct_ip
        self._fix_repro_ip_in_config(data, is_ipv6)
        with open(traffic_yml_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _setup_process_files(self, container_folder: str, process: Dict, process_folder: str, is_ipv6: bool):
        pcap_file_dst = container_folder + '/' + process['pcap']
        if not os.path.isfile(pcap_file_dst):
            shutil.copy(self.params.test_folder + '/' + process['pcap'], pcap_file_dst)
        os.makedirs(process_folder)
        config_file_dst = process_folder + '/traffic-reproducer.yml'
        shutil.copy(self.params.test_folder + '/' + process['config'], config_file_dst)

        self._build_process_traffic_yml(config_file_dst, process['pcap'], process['collector'], is_ipv6)


def prepare_pcap(params: KModuleParams):
    traffic_setup = KTrafficSetup(params)
    traffic_setup.build()
