## Test Description (207-BMP-CISCO-HUAWEI-multiple-sources-dump-spreading)

IMPORTANT: for this test we use the pmbmpd daemon (not nfacctd)!

Testing with BMP traffic from 3 different source IPs. 
BMP table dump is enabled, and configured to be spread in different intervals (depending on the scenario, see below).
The goal of this test is to validate functionality of the table dump also with the dump spreading feature.

(pcaps taken from test 202)

### Provided files:
```
- 207_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file 1 (for traffic generator)
- traffic-01.pcap                           pcap file 2 (for traffic generator)
- traffic-02.pcap                           pcap file 3 (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file
- traffic-reproducer-02.yml                 traffic replay function config file

- pmbmpd-00.conf                            pmbmpd daemon configuration file

- output-bmp-00.json                        desired pmbmpd kafka output [daisy.bmp topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Scenarios:
- Default scenario: single dump every 60s, 13 peer buckets and 1 per_peer bucket (default bucketing config)
- Scenario 01: single dump every 60s, 1 peer bucket and 10 per_peer buckets
- Scenario 02: dump spread in 4 intervals (every 30s), 13 peer buckets and 1 per_peer bucket (default bucketing config)
- Scenario 03: dump spread in 4 intervals (every 30s), 1 peer bucket and 10 per_peer buckets

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-13s: BMP packets sent 
- t=60s: BMP dump starting (for default scenario)
