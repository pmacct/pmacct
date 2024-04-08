## Test Description (101-NFv9-CISCO-cust_primitives)

NetFlow v9 from CISCO ASR9k IOS XR with IPFIX data only (template 313).

### Provided files:
```
- 101_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:   NFv9 Data-Template and Data-Records sent
- t=10s:    nfacctd producing flow data to kafka

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka (t=10s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- No ERROR or WARN messages are present in the logfile
