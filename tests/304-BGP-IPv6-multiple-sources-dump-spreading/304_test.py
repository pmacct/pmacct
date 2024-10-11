
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.test_tools as test_tools
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.', ipv6_subnet='cafe::')

@pytest.mark.ci
@pytest.mark.nfacctd
@pytest.mark.bgp
@pytest.mark.bgp_only
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Ensure traffic-reproducers are not started too near mm:05
    test_tools.avoid_time_period_in_seconds(5, 10)

    for suffix in ['a', 'b', 'c']:
        assert th.spawn_traffic_container('traffic-reproducer-304' + suffix, detached=True)

    th.set_ignored_fields(['seq', 'timestamp', 'peer_tcp_port'])
    assert th.read_and_compare_messages('daisy.bgp', 'bgp-00', 90)

    # Make sure the expected logs for bgp peer up exist in pmacct log
    th.transform_log_file_with_ip('log-00', '172.21.1.1\\d{2}|fd25::1\\d{2}')
    assert th.wait_and_check_logs('log-00', 30, 10)

    # Make sure the expected logs for bgp table dump exist
    th.transform_log_file('log-01', 'traffic-reproducer-304')
    assert th.wait_and_check_logs('log-01', 240, 10)

    # Check messages from BGP table dump
    th.set_ignored_fields(['seq', 'timestamp', 'peer_tcp_port', 'dump_period'])
    assert th.read_and_compare_messages('daisy.bgp.dump', 'bgp-dump-00', wait_time=240)

    assert not th.check_regex_in_pmacct_log('ERROR|WARN')
