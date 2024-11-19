## Test Description (208-BMP-mem-leak-test)

Testing for memory leaks with BMP traffic from 9 different source IPs (Cisco and Huawei).
After the INIT and PEER UP messages, the route-monitoring messages and stats are reproduced multiple times to generate high traffic load.

With the current configuration, traffic is sent for around 8mins, then the reproducers exit.

This test does not check any kafka output, but only verifies that the memory utilization of the pmacct container stays withing certain bounds.

### Provided files:
```
- 208_test.py                               pytest file defining test execution

- bmp-multi-sources-init.pcap               pcap file with BMP INIT messages from various sources
- bmp-multi-sources-peer-up.pcap            pcap file with BMP PEER UP messages from various sources
- bmp-multi-sources-route-monitorig.pcap    pcap file with BMP ROUTE MONITORING messages from various sources
- bmp-multi-sources-stats.pcap              pcap file with BMP STATS messages from various sources
- traffic-reproducer-configs/               folder with config files for all traffic-reproducer instances

- nfacctd-00.conf                           pmbmpd daemon configuration file

- output-log-00.txt                         log messages that need to be in the logfile
```
