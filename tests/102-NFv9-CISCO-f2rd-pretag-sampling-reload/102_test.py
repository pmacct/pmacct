
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.helpers as helpers
import shutil
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.')

@pytest.mark.ci
@pytest.mark.light
@pytest.mark.nfacctd
@pytest.mark.ipfix
@pytest.mark.ipfix_only
@pytest.mark.nfv9
@pytest.mark.avro
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)


def transform_log_file(logfile):
    helpers.replace_in_file(logfile, '/etc/pmacct', testParams.pmacct_mount_folder, 'Reading configuration file')
    helpers.replace_in_file(logfile, '.map]', '-00.map]')
    helpers.replace_in_file(logfile, 'primitives.map', 'primitives-00.map')


def main(consumers):
    th = KTestHelper(testParams, consumers)
    assert th.spawn_traffic_container('traffic-reproducer-102')

    th.set_ignored_fields(['timestamp_arrival', 'timestamp_min', 'timestamp_max', 'stamp_inserted', 'stamp_updated'])
    assert th.read_and_compare_messages('daisy.flow', 'flow-00')

    # Make sure the expected logs exist in pmacct log
    transform_log_file(testParams.log_files.get_path_like('log-00'))
    th.transform_log_file('log-00')
    assert th.check_file_regex_sequence_in_pmacct_log('log-00')
    assert not th.check_regex_in_pmacct_log('ERROR|WARN')

    # Replace -00 maps with -01 maps
    for filename in [testParams.results_mount_folder + '/' + mf for mf in ['f2rd', 'pretag', 'sampling']]:
        shutil.copyfile(filename + '-00.map', filename + '-00.map.bak')
        shutil.move(filename + '-01.map', filename + '-00.map')

    # Sending the signal to reload maps
    assert th.send_signal_to_pmacct('SIGUSR2')

    assert th.spawn_traffic_container('traffic-reproducer-102')

    assert th.read_and_compare_messages('daisy.flow', 'flow-01')

    # Make sure the expected logs exist in pmacct log
    transform_log_file(testParams.log_files.get_path_like('log-01'))
    th.transform_log_file('log-01')
    assert th.check_file_regex_sequence_in_pmacct_log('log-01')
    assert not th.check_regex_in_pmacct_log('ERROR|WARN')
