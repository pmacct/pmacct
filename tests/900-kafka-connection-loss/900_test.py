
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.scripts as scripts
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.')


@pytest.mark.signals
@pytest.mark.nfacctd
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)

    th.transform_log_file('log-00')
    assert th.wait_and_check_logs('log-00', 30, 5)
    assert not th.check_regex_in_pmacct_log('ERROR|WARN')

    th.disconnect_consumers()
    scripts.stop_and_remove_kafka_containers()

    assert th.spawn_traffic_container('traffic-reproducer-900')

    th.transform_log_file('log-01')
    assert th.wait_and_check_logs('log-01', 90, 10)

    assert th.delete_traffic_container('traffic-reproducer-900')

    # We want to leave the Kafka infrastructure running, for the next test case to use, so we re-deploy it
    assert scripts.start_kafka_containers()
    assert scripts.wait_schemaregistry_healthy(120)
