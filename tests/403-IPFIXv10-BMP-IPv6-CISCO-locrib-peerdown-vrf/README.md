## Test Description (403-IPFIXv10-BMP-IPv6-CISCO-locrib-peerdown-vrf)

Complete test with IPFIX and BMP from Cisco IOS XR 24.4.1. BMP and loc-rib and adj-rib in (glob and rd-instance). 

Over the BMP peering we receive information about multiple BGP peers, some of which are local (the router has many VRFs).

The purpose of this test is to verify the delete mechanism and to ensure that only the relevant routes for the local peer are deleted, without impacting correlation with flow on other VRFs.

### Scenarios

- Default scenario: single per-peer bucket
- Scenario-01: 10 per-peer buckets (with mpls_vpn_rd discriminator)

### Provided files:
```
- 403_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic] containing json messages [before closing sockets]
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-12s BMP session comes up and various peer_up and relative route_monitoring messages are sent
- t=17s a VRF is deconfigured from the router (VRF A2_TEST7), triggering a peer_down and some updates/withdrawals from the other peers.
- t=22-23s the VRF is re-configured (peer_up and updates are sent again for that peer).
- t=33-37s IPFIX traffic is sent (with sampling, interface and RD/VRF option data)
- t=60s pmacct producing aggregated/correlated flow records to kafka
