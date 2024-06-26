
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
import library.py.test_tools as test_tools
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd')


@pytest.mark.nfacctd
@pytest.mark.ipfix
@pytest.mark.ipfix_only
@pytest.mark.ipfixv10
@pytest.mark.nfv9
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Make sure that traffic reproducers do not start in different minutes
    test_tools.avoid_time_period_in_seconds(25, 30)
    for suffix in ['a', 'b', 'c']:
        assert th.spawn_traffic_container('traffic-reproducer-110' + suffix, detached=True)

    th.set_ignored_fields(['timestamp_arrival', 'timestamp_min', 'timestamp_max', 'stamp_inserted', 'stamp_updated'])
    assert th.read_and_compare_messages('daisy.flow', 'flow-00')

    assert not th.check_regex_in_pmacct_log('ERROR|WARN')
