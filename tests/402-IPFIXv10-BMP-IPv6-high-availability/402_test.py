
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.helpers as helpers
import library.py.json_tools as json_tools
import library.py.test_tools as test_tools
import library.py.scripts as scripts
import logging
import pytest
import time

logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd')

@pytest.mark.nfacctd
@pytest.mark.ipfix
@pytest.mark.ipfixv10
@pytest.mark.bmp
@pytest.mark.bmpv3
@pytest.mark.redis
@pytest.mark.avro
@pytest.mark.ha
def test(test_core_redis, consumer_setup_teardown):
    main(consumer_setup_teardown)

def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Loading log file into loglines list
    th.transform_log_file('log-00', 'traffic-reproducer-402')
    with open(testParams.log_files.get_path_like('log-00'), 'r') as f:
        loglines = f.read().split('\n')

    # Make sure pmacct instances started in the right order
    assert testParams.pmacct[0].process_name == 'nfacctd_core_loc_A'
    assert testParams.pmacct[1].process_name == 'nfacctd_core_loc_B'

    assert th.check_regex_sequence_in_pmacct_log([loglines[0], loglines[1]], 'nfacctd-00')
    assert th.check_regex_sequence_in_pmacct_log([loglines[0], loglines[2]], 'nfacctd-01')

    # Ensure traffic-reproducers are not started too near mm:05 (see README)
    test_tools.avoid_time_period_in_seconds(10, 15)
    assert th.spawn_traffic_container('traffic-reproducer-402', detached=True)

    # Wait until mm:05, so that BMP connections have been established (retry up to 10s to account for delays)
    test_tools.wait_until_second(5) 
    assert th.wait_and_check_regex_in_pmacct_log(loglines[3], 10, 2, 'nfacctd-00')
    assert th.wait_and_check_regex_in_pmacct_log(loglines[3], 10, 2, 'nfacctd-01')

    # Check the BMP topic (has to contain only messages from active daemon, i.e. nfacctd_00_loc_A)
    th.set_ignored_fields(['seq', 'timestamp', 'timestamp_arrival', 'bmp_router_port', 'peer_asn'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    # Check the flow topic: we need to receive the exact same messages from both daemons
    test_tools.wait_until_second(5) # Wait until mm:05 (s.t. we wait for the next minute)
    time.sleep(10) # Wait 10s to ensure that all messages will have been produced to kafka 
    output_json_file = test_tools.replace_ips_and_get_reference_file(testParams, 'flow-00')
    messages = consumers[0].get_all_pending_messages()
    logger.info('Comparing messages received with json lines in file ' + helpers.short_name(output_json_file))
    assert json_tools.compare_messages_to_json_file(messages, output_json_file, ['stamp_inserted', 'stamp_updated', 
                                                                                 'timestamp_max', 'timestamp_arrival', 
                                                                                 'timestamp_min', 'writer_id', 'peer_asn'], 
                                                                                  multi_match_allowed=True,
                                                                                  max_matches=2)

    # Ensuring all two daemons produce all the messages
    loc_A_sum = sum(1 for msg in messages if msg['writer_id'] == 'nfacctd_kafka_loc_A')
    loc_B_sum = sum(1 for msg in messages if msg['writer_id'] == 'nfacctd_kafka_loc_B')
    assert loc_A_sum == loc_B_sum

    # Check logs for ERR/WARN
    assert not th.check_regex_in_pmacct_log('ERROR|WARN', pmacct_name='nfacctd-00')
    assert not th.check_regex_in_pmacct_log('ERROR|WARN', pmacct_name='nfacctd-01')
    th.delete_traffic_container('traffic-reproducer-402')
