## Test Description (305-BGP-mem-leak-test)

Testing for memory leaks with BGP traffic from 4 different source IPs (Cisco and Huawei).
After the OPEN messages, the UPDATES messages and stats are reproduced multiple times to generate high traffic load.

With the current configuration, traffic is sent for around 7mins, then the reproducers exit.

This test does not check any kafka output, but only verifies that the memory utilization of the pmacct container stays withing certain bounds.

### Provided files:
```
- 208_test.py                               pytest file defining test execution

- bgp-multi-sources-open.pcap               pcap file with BGP OPEN messages from various sources
- bgp-multi-sources-update-keepalive.pcap   pcap file with BGP UPDATE messages from various sources

- traffic-reproducer-configs/               folder with config files for all traffic-reproducer instances

- nfacctd-00.conf                           pmbmpd daemon configuration file

- output-log-00.txt                         log messages that need to be in the logfile
```
