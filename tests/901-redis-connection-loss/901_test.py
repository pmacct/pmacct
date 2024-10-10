
from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.scripts as scripts
import library.py.helpers as helpers
import logging
import pytest
logger = logging.getLogger(__name__)

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.')

@pytest.mark.ci
@pytest.mark.light
@pytest.mark.nfacctd
@pytest.mark.redis
# added redis fixture below, that's why the test_core fixture is not used here
def test(check_root_dir, kafka_infra_setup_teardown, prepare_test, redis_setup_teardown, pmacct_setup_teardown,
         prepare_pcap, consumer_setup_teardown):
    main(consumer_setup_teardown)


def transform_log_file(logfile):
    helpers.replace_in_file(logfile, '${redis_ip}', '172.21.1.14')
    helpers.replace_in_file(logfile, '${redis_port}', '6379')


def main(consumers):
    th = KTestHelper(testParams, consumers)

    transform_log_file(testParams.log_files.get_path_like('log-00'))
    th.transform_log_file('log-00')

    logger.info('Looking for connection evidence')
    assert th.wait_and_check_logs('log-00', 10, 2)
    assert not th.check_regex_in_pmacct_log('ERROR|WARN')

    scripts.stop_and_remove_redis_container()

    transform_log_file(testParams.log_files.get_path_like('log-01'))
    th.transform_log_file('log-01')

    logger.info('Looking for lost connectivity evidence')
    assert th.wait_and_check_logs('log-01', 10, 2)
