from library.py.test_params import KModuleParams
from library.py.test_helper import KTestHelper
import library.py.test_tools as test_tools
import logging
import pytest
logger = logging.getLogger(__name__)
import time

testParams = KModuleParams(__file__, daemon='nfacctd', ipv4_subnet='192.168.100.', ipv6_subnet='cafe::')

@pytest.mark.ci
@pytest.mark.nfacctd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
@pytest.mark.memory_leak
def test(test_core, consumer_setup_teardown):
    main(consumer_setup_teardown)

def main(consumers):
    th = KTestHelper(testParams, consumers)

    for i in range(1, 10):
        th.spawn_traffic_container('repro-' + str(i), detached=True)

    th.transform_log_file_with_ip('log-00', '172.21.1.1\\d{2}')
    assert th.wait_and_check_logs('log-00', 600, 30)

    # Check for memory leaks (used memory of nfacctd container cannot exceed 100MiB)
    result, mem_util = th.memory_utilization_max_MiB("nfacctd-00", 100)
    assert result, f"Memory utilization is too high: {mem_util} MiB (expected memory utilization for this test is < 100 MiB)"
