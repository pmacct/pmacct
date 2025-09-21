import subprocess
import pytest
import os
import signal
import time
import select
from scapy.all import *
import random
import logging
from collections import defaultdict, namedtuple
import pprint

# Main test parameters
FLOWRECORD_PKTS = 1 #10

# Other
TIMEOUT_STARTUP_S = 5
TIMEOUT_SIGTERM_WAIT_S = 3
NETFLOWV9_TEMPLATE_ID = 256
NETFLOWV9_TEMPLATE_TIMER_S = 5
STARTUP_TRACE = "NetFlow Accounting Daemon, nfacctd "
PURGE_TRACE = "Purging cache - START"
NFACCTD_WAIT_TO_OUTPUT_S = 10
WAIT_TO_OUTPUT_STEP_S = 0.25
FLOWRECORD_TX_WAIT_TIME_S = 0.25

#Move this to common
def get_test_dir():
    return os.path.relpath(os.path.dirname(__file__))+"/"

def get_test_dir_outputs():
    return get_test_dir()+"outputs/"

def get_flowlogs_json_file():
    return get_test_dir_outputs()+"flowlogs.json"

def remove_json_file():
    json_file = get_flowlogs_json_file()
    if os.path.exists(json_file):
        os.remove(json_file)

def daemon_wait_for_trace(file_path, trace, timeout_s, err_msg, step_s=0.5):
    start_time = time.time()

    while True:
        with open(file_path, "r") as stderr:
            if any(trace in line for line in stderr):
                return
            time.sleep(step_s)

            if (time.time() - start_time) >= timeout_s:
                raise Exception(f"Unable to find trace '{trace}' within the {timeout_s} seconds given.")

def netflowv9_get_template(template_id=NETFLOWV9_TEMPLATE_ID):

    fields = [
        NetflowTemplateFieldV9(fieldType = "IN_BYTES", fieldLength = 4),
        NetflowTemplateFieldV9(fieldType = "IN_PKTS", fieldLength = 4),
        NetflowTemplateFieldV9(fieldType = "PROTOCOL", fieldLength = 1),
        NetflowTemplateFieldV9(fieldType = "IPV4_SRC_ADDR", fieldLength = 4),
        NetflowTemplateFieldV9(fieldType = "IPV4_DST_ADDR", fieldLength = 4),
        NetflowTemplateFieldV9(fieldType = "L4_SRC_PORT", fieldLength = 2),
        NetflowTemplateFieldV9(fieldType = "L4_DST_PORT", fieldLength = 2),
    ]
    return NetflowFlowsetV9(
        flowSetID = 0,
        templates = [
            NetflowTemplateV9(
                templateID = template_id,
                template_fields = fields,
                fieldCount = len(fields)
            )
        ]
    )

def netflowv9_template_start_sender(collector_ip, collector_port, device_ip):
    def func():
        while True:
            template_flowset = netflowv9_get_template()
            pkt = (
                IP(src = device_ip, dst = collector_ip) /
                UDP(sport = random.randint(1024, 65535), dport = collector_port) /
                NetflowHeader()/NetflowHeaderV9() /
                template_flowset
            )

            logging.debug("Sending NetflowV9 flow template")
            send(pkt, verbose = False)
            time.sleep(NETFLOWV9_TEMPLATE_TIMER_S)

    thread = threading.Thread(target = func, daemon = True)
    thread.start()

def netflowv9_flowlogs_send(collector_ip, collector_port, device_ip, num_records=1):
    """
    Generate and send NetflowV9 flow logs to a collector using Scapy.

    Parameters:
        collector_ip (str): IP address of the flow log collector.
        collector_port (int): UDP port of the flow log collector (default: 2055).
        device_ip (str): Source IP address of the exporter (default: 192.168.0.1).
        num_records (int): Number of flow records to generate

        Note: flowlog data is random
    """

    template_flowset = netflowv9_get_template()
    flow_record_class = GetNetflowRecordV9(template_flowset)

    # Generate individual records
    records = []
    for _ in range(num_records):
        n_pkts = random.randint(1, 1000)
        n_bytes = n_pkts*random.randint(64,1500)

        record = flow_record_class(
                    #Workaround scapy bug https://github.com/secdev/scapy/issues/4810
                    #IN_BYTES = n_bytes,
                    #IN_PKTS = n_pkts,
                    IN_BYTES = n_bytes.to_bytes(4, 'big'),
                    IN_PKTS = n_pkts.to_bytes(4, 'big'),
                    PROTOCOL = 6,
                    IPV4_SRC_ADDR = "192.168.0.10",
                    IPV4_DST_ADDR = "192.168.0.11",
                    L4_SRC_PORT = random.randint(1024, 65535),
                    L4_DST_PORT = 80)
        records.append(record)

    # Prepare the final packet
    dataflowset = NetflowDataflowsetV9(
                    templateID = NETFLOWV9_TEMPLATE_ID,
                    records = records)
    pkt = (
        IP(src = device_ip, dst = collector_ip) /
        UDP(sport = random.randint(1024, 65535), dport = collector_port) /
        NetflowHeader()/NetflowHeaderV9() /
        dataflowset
    )

    send(pkt, verbose=False)

    logging.debug(f"Sent {num_records} flow logs to {collector_ip}:{collector_port}.")
    #logging.debug(f"Pkt:\n{pkt.show(dump=True)}")

    return records

@pytest.fixture(scope="module")
def nfacctd_setup():
    stdout_file = get_test_dir_outputs()+"nfacctd.stdout"
    stderr_file = get_test_dir_outputs()+"nfacctd.stderr"

    # Create outputs/ folder if necessary
    os.makedirs(get_test_dir_outputs(), exist_ok=True)

    # Remove previous execution flowlogs
    remove_json_file()

    with open(stdout_file, "w") as stdout, open(stderr_file, "w") as stderr:
        proc = subprocess.Popen(
            ["nfacctd", "-f", "nfacctd.conf"],
            stdout = stdout,
            stderr = stderr,
            text = True,
            preexec_fn = os.setsid,
            cwd = get_test_dir()
        )

    #daemon_wait_for_trace(stderr_file, STARTUP_TRACE, TIMEOUT_STARTUP_S, "Unable to capture startup trace for nfacctd")
    daemon_wait_for_trace(stderr_file, PURGE_TRACE, TIMEOUT_STARTUP_S, "Unable to capture first purging cache trace")

    logging.debug("nfacctd started (purge trace captured)...")

    yield proc

    # Teardown
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout = TIMEOUT_SIGTERM_WAIT_S)
    except Exception as e:
        logging.warning("WARNING: unable to cleanly terminate() nfacctd")
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)

def nfv9records_to_dict(records, flowlogs):
    for r in records:
        key = (r.IPV4_SRC_ADDR, r. IPV4_DST_ADDR, r.PROTOCOL, r.L4_SRC_PORT, r.L4_DST_PORT)
        flowlogs[key]["pkts"] += int.from_bytes(r.IN_PKTS, 'big') #r.IN_PKTS
        flowlogs[key]["bytes"] += int.from_bytes(r.IN_BYTES, 'big') #r.IN_BYTES
    return flowlogs

def flowlogs_json_to_dict(flowlogs=None):
    flowlogs = defaultdict(lambda: {"pkts": 0, "bytes": 0})

    flowlogs_json_file = get_flowlogs_json_file()
    if not os.path.exists(flowlogs_json_file):
        return flowlogs

    with open(flowlogs_json_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)

            proto_str = r["ip_proto"].lower().strip()
            ip_proto = IP().get_field("proto").s2i.get(proto_str)
            key = (r["ip_src"], r["ip_dst"], ip_proto, r["port_src"], r["port_dst"])

            flowlogs[key]["pkts"] += r.get("packets", 0)
            flowlogs[key]["bytes"] += r.get("bytes", 0)

    return flowlogs

def compare_flowlogs(flowlogs1, flowlogs2):
    for key in flowlogs1:
        if key not in flowlogs2:
            return False
        if flowlogs1[key]["pkts"] != flowlogs2[key]["pkts"]:
            return False
        if flowlogs1[key]["bytes"] != flowlogs2[key]["bytes"]:
            return False
    return True

def test_nfacctd_nfv9_basic_accounting(nfacctd_setup):
    """Test nfacctd basic account functionality with NetflowV9."""
    nfacctd_proc = nfacctd_setup

    collector_ip = "127.0.0.1"
    collector_port = 2055
    device_ip = "100.64.0.1"

    # Start beacon
    netflowv9_template_start_sender(collector_ip, collector_port, device_ip)

    # Inject flowlogs
    flowlogs = defaultdict(lambda: {'pkts': 0, 'bytes': 0})

    for i in range(0, FLOWRECORD_PKTS):
        records = netflowv9_flowlogs_send(collector_ip, collector_port, device_ip)
        flowlogs = nfv9records_to_dict(records, flowlogs)
        time.sleep(FLOWRECORD_TX_WAIT_TIME_S)

    logging.debug(f"Injected:\n"+pprint.pformat(flowlogs))

    # Give some time to nfacctd to output results into the json file
    for i in range(0, int(NFACCTD_WAIT_TO_OUTPUT_S/WAIT_TO_OUTPUT_STEP_S)):
        json_flowlogs = flowlogs_json_to_dict()
        if compare_flowlogs(flowlogs, json_flowlogs):
            break
        time.sleep(WAIT_TO_OUTPUT_STEP_S)

    logging.debug(f"nfacctd flowlogs:\n"+pprint.pformat(json_flowlogs))

    assert compare_flowlogs(flowlogs, json_flowlogs)
