###################################################
# Automated Testing Framework for Network Analytics
# Central fixtures definition; used by all tests
# nikolaos.tsokas@swisscom.com 11/05/2023
###################################################

import library.py.scripts as scripts
import library.py.setup_test as setup_test
import library.py.setup_pcap as setup_pcap
import logging
import pytest
import os
import time
import library.py.helpers as helpers
from library.py.kafka_consumer import KMessageReaderAvro, KMessageReaderPlainJson, KMessageReaderList

logger = logging.getLogger(__name__)


# Defines parameter for receiving configuration in the form <test case>:<scenario>
def pytest_addoption(parser):
    parser.addoption("--runconfig", action="store", default="")


# Runs for every test case collected by pytest from the files. By parameterizing the metafunc object, we create
# clones of the test case for every possible scenario, i.e., for every scenario, for which a subfolder exists.
# The "scenario_name" parameter is available to all function-level fixtures that need it, just by them declaring it
# as input parameter along with "request".
def pytest_generate_tests(metafunc):
    scen_folders = helpers.select_files(metafunc.module.testParams.test_folder, 'scenario-\\d{2}$')
    scenarios = ['default'] + [os.path.basename(s) for s in scen_folders if os.path.isdir(s)]
    logger.debug('Test ' + os.path.basename(os.path.dirname(metafunc.module.__file__)) +
                 ' is cloned for following scenarios: ' + str(scenarios))
    metafunc.parametrize('scenario_name', scenarios, scope='function')


# Runs at the end of the pytest collection process. Restricts test case execution to the selected
# scenarios (not selected scenarios are skipped)
def pytest_collection_modifyitems(config, items):
    runconfig = config.getoption('runconfig').replace('*', '').split('_')
    config_tuples = []
    for rc in runconfig:
        rclist = rc.split(':')
        test_prefix = rclist[0]
        selected_scenario = '<all scenarios>'
        if len(rclist) > 1 and rclist[1] != '':
            selected_scenario = 'scenario-' + rclist[1] if rclist[1] != '00' else 'default'
        config_tuples.append((test_prefix, selected_scenario))
    logger.info('Selected scenario per test case:' + str(config_tuples))
    skip = pytest.mark.skip(reason="Scenario not selected - skipped")
    count_skipped = 0
    for item in items:
        for tpl in config_tuples:
            if os.path.basename(item.module.testParams.test_folder).startswith(tpl[0]):
                if tpl[1] != '<all scenarios>' and not item.name.endswith('[' + tpl[1] + ']'):
                    logger.debug('Skipping ' + os.path.basename(item.module.testParams.test_folder) + item.name +
                                 ' (scenario not selected)')
                    count_skipped += 1
                    item.add_marker(skip)
    if count_skipped > 0:
        logger.info('Skipping ' + str(count_skipped) + ' of ' + str(len(items)) + ' collected items')


# Fixture makes sure the framework is run from the right directory
@pytest.fixture(scope="session")
def check_root_dir():
    logger.debug('Framework runs from directory: ' + os.getcwd())
    assert all(x in os.listdir(os.getcwd()) for x in ['tools', 'library', 'pytest.ini', 'settings.conf'])


# The setup part of the Kafka insfrastructure fixture
def setup_kafka_infra():
    assert not scripts.check_broker_running()
    assert scripts.create_test_network()
    assert scripts.start_kafka_containers()
    assert scripts.wait_schemaregistry_healthy(120)


# Setup and teardown fixture for Kafka infrastructure (zookeeper, schema-registry and broker)
@pytest.fixture(scope="session")
def kafka_infra_setup_teardown():
    setup_kafka_infra()
    yield
    scripts.stop_and_remove_kafka_containers()
    scripts.delete_test_network()


# Setup only fixture - for troubleshooting/debugging only!
@pytest.fixture(scope="session")
def kafka_infra_setup():
    setup_kafka_infra()


# This is the top level of function-scoped fixture, therefore it gets the scenario param
# Adds a banner with the test case name to the logs at the start and the end of the execution
@pytest.fixture(scope="function")
def log_test_and_scenario(scenario_name, request):
    params = request.module.testParams

    def log_message(msg):
        txts = ['*' * len(msg), '*' * len(msg), msg, '*' * len(msg), '*' * len(msg)]
        for txt in txts:
            logger.info(txt)

    test_and_scenario = 'test: ' + params.test_name + ', scenario: ' + scenario_name
    log_message('** Starting ' + test_and_scenario + ' **')
    # pmacct is not yet running, therefore no concurrency issues with monitor.sh are expected, even though
    # logging to the same file
    with open(request.module.testParams.monitor_file, 'a') as f:
        f.write('** Starting ' + test_and_scenario + ' **\n')
    yield
    log_message('** Finishing ' + test_and_scenario + ' **')


# Prepares results folder to receive logs and output from pmacct
@pytest.fixture(scope="function")
def prepare_test(scenario_name, request):
    logger.info('Scenario selected: ' + scenario_name)
    setup_test.prepare_test_env(request.module.testParams, scenario_name)


# Prepares Kafka topic, creates kafka-compose file for pmacct and deploys pmacct containers
def setup_pmacct(params):
    assert len(params.pmacct) > 0 and os.path.isfile(params.results_conf_file)
    for topic in list(params.kafka_topics.values()):
        assert scripts.create_or_clear_kafka_topic(topic)
    setup_test.create_pmacct_compose_files(params)
    for pmacct in params.pmacct:
        assert scripts.start_pmacct_container(pmacct.name, pmacct.docker_compose_file)
        assert scripts.wait_pmacct_running(pmacct.name, 5)  # wait 5 seconds
        time.sleep(5)


# Setup and Teardown fixture for pmacct container
@pytest.fixture(scope="function")
def pmacct_setup_teardown(request):
    params = request.module.testParams
    setup_pmacct(params)
    yield
    for folder in params.traffic_folders:
        scripts.stop_and_remove_traffic_container(folder)
    logger.debug('There are ' + str(len(params.pmacct)) + " pmacct instances running")
    for pmacct in reversed(params.pmacct):
        rsc_msg = [pmacct.name + ' container resources:']
        rsc_msg += [' ' + x for x in helpers.container_resources_string(scripts.get_pmacct_stats(pmacct.name))]
        for msg in rsc_msg:
            logger.info(msg)
        scripts.stop_and_remove_pmacct_container(pmacct.name, pmacct.docker_compose_file)


# Pmacct setup only - for troubleshooting/debugging only!
@pytest.fixture(scope="function")
def pmacct_setup(request):
    setup_pmacct(request.module.testParams)


# Waits for the first characteristic lines to appear in pmacct logs, to be sure pmacct instances are running.
# Also the versions of pmacct are logged to the test logger.
@pytest.fixture(scope="function")
def pmacct_logcheck(request):
    params = request.module.testParams
    for pmacct in params.pmacct:
        assert helpers.retry_until_true('Pmacct first log line', lambda: os.path.isfile(pmacct.pmacct_log_file) and
                                        helpers.check_regex_sequence_in_file(pmacct.pmacct_log_file,
                                        ['_core.*/core .+ waiting for .+ data on interface']), 30, 5)
        pmacct_version = helpers.read_pmacct_version(pmacct.pmacct_log_file)
        assert pmacct_version
        logger.info(pmacct.name + ' version: ' + pmacct_version)


# Prepares folders with pcap information for traffic-reproduction containers to mount
@pytest.fixture(scope="function")
def prepare_pcap(request):
    setup_pcap.prepare_pcap(request.module.testParams)


# Sets up the Kafka consumers for all Kafka topics mentioned in the pmacct configuration file.
# By convention, all topics are considered to use avro, unless their name ends with "_json", in
# which case they are considered plain json.
def setup_consumers(request):
    params = request.module.testParams
    consumers = KMessageReaderList()
    os.makedirs(params.results_dump_folder)
    for k in params.kafka_topics.keys():
        topic_name = '_'.join(params.kafka_topics[k].split('.')[0:-1])
        message_reader_class = KMessageReaderAvro
        if topic_name.endswith('_json'):
            message_reader_class = KMessageReaderPlainJson
        msg_dump_file = params.results_dump_folder + '/' + topic_name + '_dump'
        consumer = message_reader_class(params.kafka_topics[k], msg_dump_file)
        consumer.connect()
        consumers.append(consumer)
    logger.debug('Local setup Consumers ' + str(consumers))
    return consumers


def teardown_consumers(consumers):
    logger.debug('Local teardown Consumers ' + str(consumers))
    for consumer in consumers:
        consumer.disconnect()


# Setup and teardown fixture for Kafka consumers
@pytest.fixture(scope="function")
def consumer_setup_teardown(request):
    consumers = setup_consumers(request)
    yield consumers
    teardown_consumers(consumers)


# Setup and teardown fixture for Redis
@pytest.fixture(scope="function")
def redis_setup_teardown():
    assert scripts.start_redis_container()
    assert scripts.wait_redis_running(5)  # wait up to 5 seconds
    yield
    scripts.stop_and_remove_redis_container()


# No kafka and no teardown - only for debugging
@pytest.fixture(scope="function")
def debug_core(check_root_dir, prepare_test, pmacct_setup, prepare_pcap):
    pass


# No kafka (use with kafka already up) - for speeding up in test-case development & demos
@pytest.fixture(scope="function")
def test_core_no_kafka(check_root_dir, log_test_and_scenario, prepare_test, pmacct_setup_teardown,
                       pmacct_logcheck, prepare_pcap):
    pass


# Abstract fixture, which incorporates all common (core) fixtures
@pytest.fixture(scope="function")
def test_core(check_root_dir, kafka_infra_setup_teardown, log_test_and_scenario, prepare_test,
              pmacct_setup_teardown, pmacct_logcheck, prepare_pcap):
    pass


# Abstract fixture, which incorporates all common (core) fixtures and redis
@pytest.fixture(scope="function")
def test_core_redis(check_root_dir, kafka_infra_setup_teardown, log_test_and_scenario, prepare_test,
                    redis_setup_teardown, pmacct_setup_teardown, pmacct_logcheck, prepare_pcap):
    pass
