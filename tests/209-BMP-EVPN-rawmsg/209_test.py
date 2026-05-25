import json
import re
from pathlib import Path

import pytest
from library.py.test_params import KModuleParams

testParams = KModuleParams(__file__, daemon="nfacctd")


def _read_samples():
    fixture = Path(__file__).with_name("evpn-rawmsg-samples.json")
    with fixture.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.ci
@pytest.mark.nfacctd
@pytest.mark.bmp
@pytest.mark.bmp_only
@pytest.mark.bmpv3
def test_evpn_rawmsg_route_types_covered(scenario_name):
    samples = _read_samples()

    assert len(samples) == 5
    route_types = {s["evpn_route_type"] for s in samples}
    assert route_types == {1, 2, 3, 4, 5}

    raw_msg_re = re.compile(r"^0x[0-9A-F]+$")
    for sample in samples:
        assert sample["afi"] == 25
        assert sample["safi"] == 70
        assert raw_msg_re.match(sample["raw_msg"])

    by_rt = {s["evpn_route_type"]: s for s in samples}

    # RT-1 Ethernet Auto-Discovery: route distinguisher + ESI expected.
    assert by_rt[1]["evpn_rd"]
    assert by_rt[1]["evpn_esi"]

    # RT-2 MAC/IP Advertisement: MAC plus label expected.
    assert by_rt[2]["evpn_mac"]
    assert by_rt[2]["evpn_label"] is not None

    # RT-3 Inclusive Multicast: originator IP expected.
    assert by_rt[3]["evpn_originator_ip"]

    # RT-4 Ethernet Segment: at least ESI should be parsed.
    assert by_rt[4]["evpn_esi"] or by_rt[4].get("evpn_originator_ip")

    # RT-5 IP Prefix: prefix, gateway IP, and label expected.
    assert by_rt[5]["evpn_prefix"]
    assert by_rt[5]["evpn_gw_ip"]
    assert by_rt[5]["evpn_label"] is not None
