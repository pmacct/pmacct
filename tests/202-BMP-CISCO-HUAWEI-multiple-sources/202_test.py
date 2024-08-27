
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='pmbmpd', ipv4_subnet='192.168.100.')


@pytest.mark.pmbmpd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
@pytest.mark.basic
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)
    for suffix in ['a', 'b', 'c']:
        th.spawn_traffic_container('traffic-reproducer-202' + suffix, detached=True)

    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    # Make sure the expected logs exist in pmacct log
    th.transform_log_file_with_ip('log-00', '172.21.1.1\\d{2}')
    assert th.check_file_regex_sequence_in_pmacct_log('log-00')
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.101] BMP peers usage')
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.102] BMP peers usage')
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.103] BMP peers usage')

    for suffix in ['a', 'b', 'c']:
        th.delete_traffic_container('traffic-reproducer-202' + suffix)

    # Make sure the expected logs exist in pmacct log
    th.transform_log_file_with_ip('log-01', '172.21.1.1\\d{2}')
    assert th.wait_and_check_logs('log-01', 30, 10)

    assert not th.check_regex_in_pmacct_log('ERROR|WARN(?!(.*Unable to get kafka_host)|(.*connect to redis server))')
