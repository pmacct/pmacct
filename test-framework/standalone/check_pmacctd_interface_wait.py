#!/usr/bin/env python3
"""Exercise a compiled pmacctd's single-interface wait behavior on Linux.

Run explicitly: sudo ./check_pmacctd_interface_wait.py /path/to/src/pmacctd
Requires Python 3, iproute2, util-linux unshare, and privileges for network namespaces, veth creation, and packet capture (normally root).
Build pmacctd with libpcap, --enable-l2 and --enable-jansson. No installation is needed.
Each case uses a fresh network namespace; no external traffic is sent.
Runtime is about 90 seconds. This standalone script is not collected by pytest.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


CASES = ("absent_wait", "delayed_capture", "startup_capture", "absent_no_wait")
INTERFACE = "pmacct-test"
PEER = "pmacct-peer"


def run(*command):
    subprocess.run(command, check=True)


def create_interfaces():
    run("ip", "link", "add", INTERFACE, "type", "veth", "peer", "name", PEER)
    run("ip", "link", "set", INTERFACE, "address", "02:00:00:00:00:01", "up")
    run("ip", "link", "set", PEER, "address", "02:00:00:00:00:02", "up")
    run("ip", "address", "add", "192.0.2.2/24", "dev", PEER)
    run("ip", "neighbor", "add", "192.0.2.1", "lladdr", "02:00:00:00:00:01",
        "nud", "permanent", "dev", PEER)


def require_running(process):
    status = process.poll()
    if status is not None:
        if status < 0:
            raise AssertionError("collector received " + signal.Signals(-status).name)
        raise AssertionError("collector exited with status " + str(status))


def survive_until(process, deadline):
    while time.monotonic() < deadline:
        require_running(process)
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    require_running(process)


def capture(process, output):
    deadline = time.monotonic() + 20
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind(("192.0.2.2", 12345))
        while time.monotonic() < deadline:
            require_running(process)
            sender.sendto(b"pmacct interface wait regression", ("192.0.2.1", 54321))
            if output.exists():
                for line in output.read_text().splitlines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # The print plugin may still be writing this record.
                    if (record.get("ip_src") == "192.0.2.2"
                            and record.get("ip_dst") == "192.0.2.1"
                            and record.get("packets", 0) > 0):
                        print("captured: " + json.dumps(record), flush=True)
                        return
            time.sleep(0.1)
    raise AssertionError("no JSON packet capture from 192.0.2.2 to 192.0.2.1")


def stop_group(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    process.wait()


def case(binary, name):
    process = None
    with tempfile.TemporaryDirectory(prefix="pmacct-interface-wait-", dir="/tmp") as directory:
        directory = Path(directory)
        output = directory / "flows.json"
        config = directory / "pmacctd.conf"
        log = directory / "collector.log"
        config.write_text(
            "daemonize: false\n"
            "pcap_interface: pmacct-test\n"
            "pcap_interface_wait: " + ("false" if name == "absent_no_wait" else "true") + "\n"
            "plugins: print\n"
            "aggregate: src_host, dst_host\n"
            "print_output: json\n"
            "print_refresh_time: 1\n"
            "print_output_file: " + str(output) + "\n"
            "print_output_file_append: true\n"
        )
        try:
            if name == "startup_capture":
                create_interfaces()
            with log.open("w") as stream:
                process = subprocess.Popen([str(binary), "-f", str(config)],
                                           stdout=stream, stderr=stream,
                                           cwd=directory, start_new_session=True)
                started = time.monotonic()
                if name == "absent_wait":
                    survive_until(process, started + 40)
                elif name == "delayed_capture":
                    survive_until(process, started + 35)
                    create_interfaces()
                    capture(process, output)
                elif name == "startup_capture":
                    capture(process, output)
                else:
                    status = process.wait(timeout=10)
                    if status <= 0:
                        raise AssertionError("expected nonzero exit without signal, got " + str(status))
        except BaseException:
            if process is not None:
                stop_group(process)
                process = None
            if log.exists():
                print(log.read_text(), file=sys.stderr, flush=True)
            raise
        finally:
            if process is not None:
                stop_group(process)
            links = json.loads(subprocess.check_output(["ip", "-json", "link", "show"]))
            if any(link["ifname"] == INTERFACE for link in links):
                run("ip", "link", "delete", INTERFACE)


def interrupted(signum, frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pmacctd", type=Path, help="compiled pmacctd with L2 and JSON support")
    parser.add_argument("--case", choices=CASES, help=argparse.SUPPRESS)
    parser.add_argument("--parent-network-namespace", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.pmacctd.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("pmacctd must be an executable file")
    for tool in ("ip", "unshare"):
        if shutil.which(tool) is None:
            parser.error("required command not found: " + tool)
    namespace = os.readlink("/proc/self/ns/net")
    signal.signal(signal.SIGTERM, interrupted)
    if args.case:
        if not args.parent_network_namespace or namespace == args.parent_network_namespace:
            parser.error("refusing network changes without a fresh network namespace")
        case(binary, args.case)
        return 0
    failed = 0
    for name in CASES:
        started = time.monotonic()
        process = subprocess.Popen(["unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                                    str(binary), "--case", name,
                                    "--parent-network-namespace", namespace])
        try:
            status = process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()
        print("{} {} ({:.1f}s)".format("PASS" if status == 0 else "FAIL", name,
                                      time.monotonic() - started), flush=True)
        failed += status != 0
    print("{} passed; {} failed".format(len(CASES) - failed, failed), flush=True)
    return int(failed != 0)


if __name__ == "__main__":
    sys.exit(main())
