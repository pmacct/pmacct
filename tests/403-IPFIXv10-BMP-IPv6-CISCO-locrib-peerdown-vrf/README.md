## Test Description (403-IPFIXv10-BMP-IPv6-CISCO-locrib-peerdown-vrf)

Complete test with IPFIX and BMP from Cisco IOS XR 24.4.1. BMP and loc-rib and adj-rib in (glob and rd-instance). 

Over the BMP peering we receive information about multiple BGP peers, some of which are local (the router has many VRFs).

At t=17.550s a VRF is deconfigured from the router (VRF A2_TEST7), triggering a peer_down and some updates/withdrawals from the other peers.
At t=17.760s the VRF is re-configured (peer_up and updates are sent again for that peer).

The purpose of this test is to verify the delete mechanism and to ensure that only the relevant routes for the local peer are deleted.

### Provided files:
```
- 403_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic] containing json messages [before closing sockets]
```
