
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='pmtelemetryd', ipv4_subnet='192.168.100.')


import library.py.test_tools as test_tools  

@pytest.mark.ci
@pytest.mark.yang
@pytest.mark.udp_notif
@pytest.mark.json
@pytest.mark.pmtelemetryd
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)

def main(consumers):
    th = KTestHelper(testParams, consumers)
    assert th.spawn_traffic_container('traffic-reproducer')

    th.set_ignored_fields(['timestamp', 'telemetry_port', 'telemetry_node_port'])
    assert th.read_and_compare_messages('daisy.device', 'device-00')

    # consumer = consumers.get_consumer_of_topic_like('daisy.device')
    # assert test_tools.read_messages_dump_only(consumer, testParams, wait_time=30)

    assert not th.check_regex_in_pmacct_log('ERROR|WARN')
