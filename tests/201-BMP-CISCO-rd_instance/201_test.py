
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.')


@pytest.mark.nfacctd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)
    assert th.spawn_traffic_container('traffic-reproducer-201')

    th.set_ignored_fields(['seq', 'timestamp', 'bmp_router_port', 'timestamp_arrival', 'peer_asn'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    th.transform_log_file('log-00', 'traffic-reproducer-201')
    assert th.wait_and_check_logs('log-00', 30, 10)
    assert not th.check_regex_in_pmacct_log('ERROR|WARN(?!.*Unable to get kafka_host)')
