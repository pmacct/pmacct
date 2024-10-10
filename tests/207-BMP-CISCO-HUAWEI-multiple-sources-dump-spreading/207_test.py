
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.test_tools as test_tools
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='pmbmpd', ipv4_subnet='192.168.100.')

@pytest.mark.ci
@pytest.mark.pmbmpd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Ensure traffic-reproducers are not started too near mm:05
    test_tools.avoid_time_period_in_seconds(10, 10)

    for suffix in ['a', 'b', 'c']:
        th.spawn_traffic_container('traffic-reproducer-207' + suffix, detached=True)

    # TODO DAISY: investigate why with table dump enabled bgp_nexthop sometimes changes to :ffff...
    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port', 'bgp_nexthop'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    # Make sure the expected logs exist in pmacct log
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.101] BMP peers usage')
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.102] BMP peers usage')
    assert th.check_regex_in_pmacct_log('\\[172\\.21\\.1\\.103] BMP peers usage')
    assert not th.check_regex_in_pmacct_log('ERROR|WARN(?!.*Unable to get kafka_host)')

    # Check logs
    th.transform_log_file('log-00', 'traffic-reproducer-207')
    assert th.wait_and_check_logs('log-00', 120, 10)

    # Check messages from BMP table dump
    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port', 'dump_period'])
    assert th.read_and_compare_messages('daisy.bmp.dump', 'bmp-dump-00', wait_time=120)
