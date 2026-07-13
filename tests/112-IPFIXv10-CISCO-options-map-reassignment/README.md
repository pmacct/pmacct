## Test Description (112-IPFIXv10-CISCO-options-map-reassignment)

IPFIXv10 from a Cisco router testing correct enrichment of flow data when IPFIX Options Data
records reassign VRF IDs to new VRF names, MPLS VPN Route Distinguishers, and interface names.

This test covers the bugs fixed in:
- `fix(nfacctd): replace stale vrf_name_map entry on VRF ID reassignment`
- `fix(nfacctd): replace stale in_rd_map, out_rd_map and iface_name_map entries on ID reassignment`

The root cause in both cases was that `cdada_map_insert()` silently ignores updates to existing
keys (returns `CDADA_E_EXISTS`), leaving stale entries in `vrf_name_map`, `in_rd_map`,
`out_rd_map`, and `iface_name_map` permanently when a router reassigns its internal VRF IDs.

### Provided files:
```
- 112_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd           HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     custom primitives definition (vrf_id_ingress/egress)

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
```

### Scenario

The PCAP simulates a Cisco router that reassigns its internal VRF IDs by sending two rounds of
IPFIX Options Data records for the same VRF ID keys:

| Round | VRF ID     | VRF Name   | MPLS VPN RD        | Interface            |
|-------|------------|------------|--------------------|----------------------|
| 1     | 1610612740 | A2_TEST_1  | 0002fbf0005a076d   | TenGigE0/0/0/16.121  |
| 2     | 1610612740 | A2_TEST_0  | 0002fbf0005a0385   | TenGigE0/0/0/16.100  |

Flow data arriving after the second Options Data round must be enriched using the updated
values (`A2_TEST_0`, updated RD, updated interface name), not the stale initial ones.

Without the fixes, nfacctd would permanently retain the first mapping for VRF ID `1610612740`
and all subsequent flows would be incorrectly enriched with `A2_TEST_1`, the old RD, and the
old interface. The daemon would hold this wrong state until restarted.

### Test timeline:

t=0s → traffic-reproducer startup

- t=0s:   Initial IPFIX Options Data records sent (VRF → name/RD/iface, round 1)
- t=19s:  IPFIX Data Records (flow data) sent — must be enriched using round-1 mappings
- t=41s:  Updated IPFIX Options Data records sent (VRF ID reassignment, round 2)
- t=43s:  IPFIX Data Records (flow data) sent — must be enriched using round-2 mappings
