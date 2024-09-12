
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd')


@pytest.mark.nfacctd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
@pytest.mark.basic
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)
    assert th.spawn_traffic_container('traffic-reproducer-204', detached=True)

    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port', 'peer_asn'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    assert not th.check_regex_in_pmacct_log('ERROR|WARN')
