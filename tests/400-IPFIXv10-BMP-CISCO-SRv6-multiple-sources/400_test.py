
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd')


@pytest.mark.nfacctd
@pytest.mark.ipfix
@pytest.mark.ipfixv10
@pytest.mark.bmp
@pytest.mark.bmpv3
@pytest.mark.basic
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Reproduce pcap traffic
    assert th.spawn_traffic_container('traffic-reproducer-400a', detached=True)
    assert th.spawn_traffic_container('traffic-reproducer-400b', detached=True)

    # Compare received messages on topic daisy.flow to reference file output-flow-00.json
    th.set_ignored_fields(['stamp_inserted', 'stamp_updated', 'timestamp_max', 'timestamp_arrival', 'timestamp_min'])
    assert th.read_and_compare_messages('daisy.flow', 'flow-00')

    # Compare received messages on topic daisy.bmp to reference file output-bmp-00.json
    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    # Check logs for BMP peer up notification
    th.transform_log_file('log-00')
    assert th.check_file_regex_sequence_in_pmacct_log('log-00')
    assert not th.check_regex_in_pmacct_log('ERROR|WARN(?!(.*Unable to get kafka_host)|(.*connect to redis server))')

    # Close connections and check logs
    logger.info('Stopping traffic container (closing TCP connections)')
    assert th.delete_traffic_container('traffic-reproducer-400a')
    assert th.delete_traffic_container('traffic-reproducer-400b')

    # Compare received messages on topic daisy.bmp to reference file output-bmp-01.json
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-01')
