## Test Description (304-BGP-IPv6-multiple-sources-dump-spreading)

Testing with BGP traffic from 3 senders (mix ipv4 and ipv6), with 3 different source IPs. 
BGP table dump is enabled, and configured to be spread in different intervals (depending on the scenario, see below). 
The goal of this test is to validate functionality of the table dump also with the dump spreading feature.

(pcaps taken from test 302)

### Provided files:
```
- 304_test.py                               pytest file defining test execution

- traffic-01.pcap                           pcap file (for traffic reproducer)
- traffic-02.pcap                           pcap file (for traffic reproducer)
- traffic-02.pcap                           pcap file (for traffic reproducer)
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file
- traffic-reproducer-02.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages
- output-bgp-dump-00.json                   desired nfacctd kafka output [daisy.bgp.dump topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Scenarios:

- Default scenario: single dump every 60s, no spreading
- Scenario 01: dump spread in 8 intervals (every 30s)
- Scenario 02: dump spread in 9 intervals (every 20s)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

pcaps file time duration: 
- t=5-7s: BGP packets sent (from reproducers 00-02)
