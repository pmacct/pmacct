
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
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.redis
@pytest.mark.avro
@pytest.mark.ha
def test(test_core_redis, consumer_setup_teardown):
    main(consumer_setup_teardown)

def main(consumers):
    th = KTestHelper(testParams, consumers)

    # Loading log file into loglines list
    th.transform_log_file('log-00', 'traffic-reproducer-206')
    with open(testParams.log_files.get_path_like('log-00'), 'r') as f:
        loglines = f.read().split('\n')

    # Make sure pmacct instances started in the right order
    assert testParams.pmacct[0].process_name == 'nfacctd_core_loc_A'
    assert testParams.pmacct[1].process_name == 'nfacctd_core_loc_B'

    assert th.check_regex_sequence_in_pmacct_log([loglines[0], loglines[1]], 'nfacctd-00')
    assert th.check_regex_sequence_in_pmacct_log([loglines[0], loglines[2]], 'nfacctd-01')

    # Ensure traffic-reproducers are not started too near mm:05 (see README)
    test_tools.avoid_time_period_in_seconds(10, 15)
    assert th.spawn_traffic_container('traffic-reproducer-206', detached=True)

    # Wait until mm:05, so that BMP connections have been established (retry up to 20s to account for delays)
    test_tools.wait_until_second(5) 
    assert th.wait_and_check_regex_in_pmacct_log(loglines[3], 20, 2, 'nfacctd-00')
    assert th.wait_and_check_regex_in_pmacct_log(loglines[3], 20, 2, 'nfacctd-01')

    # Start HA Failover Scenarios
    time.sleep(20)
    scripts.stop_and_remove_redis_container()       # Simulate redis outage
    assert th.wait_and_check_regex_sequence_in_pmacct_log([loglines[2], loglines[1]], 10, 2, 'nfacctd-01')

    time.sleep(5)
    scripts.start_redis_container()                 # Bring redis back up
    assert th.wait_and_check_regex_sequence_in_pmacct_log([loglines[2], loglines[1], loglines[2]], 10, 2, 'nfacctd-01')

    time.sleep(5)
    nfacctd_00 = testParams.get_pmacct_with_name('nfacctd-00')
    scripts.stop_and_remove_pmacct_container(nfacctd_00.name, nfacctd_00.docker_compose_file)   # Simulate active daemon crashing
    assert th.wait_and_check_regex_sequence_in_pmacct_log([loglines[2], loglines[1], loglines[2], loglines[1]], 
                                                          10, 2, 'nfacctd-01')

    time.sleep(5)
    scripts.start_pmacct_container(nfacctd_00.name, nfacctd_00.docker_compose_file)             # Bring daemon back up
    assert th.wait_and_check_regex_sequence_in_pmacct_log([loglines[1], loglines[2]], 10, 2, 'nfacctd-00')

    # Compare BMP Init Message (timestamp is not from packets and cannot be matched)
    th.set_ignored_fields(['timestamp', 'bmp_router_port', 'timestamp_arrival', 'writer_id'])
    assert th.read_and_compare_messages('daisy.bmp', 'bmp-00')

    # Compare all other received messages to reference file output-bgp-01.json
    messages = consumers[0].get_all_pending_messages()
    output_json_file = test_tools.replace_ips_and_get_reference_file(testParams, 'bmp-01')
    logger.info('Comparing messages received with json lines in file ' + helpers.short_name(output_json_file))
    assert json_tools.compare_messages_to_json_file(messages, output_json_file, ['seq', 'bmp_router_port',
                                                                                 'timestamp_arrival','writer_id'], 
                                                                                 multi_match_allowed=True)

    # Ensuring all 2 writer_id's show up in the messages
    writer_ids = set([msg['writer_id'] for msg in messages])
    logger.info('There are messages from ' + str(len(writer_ids)) + ' different pmacct processes: ' + str(writer_ids))
    assert len(writer_ids) == 2

    assert not th.check_regex_in_pmacct_log('ERROR', pmacct_name='nfacctd-00')
    assert not th.check_regex_in_pmacct_log('ERROR', pmacct_name='nfacctd-01')

    th.delete_traffic_container('traffic-reproducer-206')
