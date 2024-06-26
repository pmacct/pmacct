## Test Description (111-IPFIXv10-NFv9-IPv6-IPv4-mix_sources)

Test with IPFIX and NFv9 from 2 different source IPs, one ipv4 and the other ipv6, sending data to the same nfacctd daemon.

### Provided files:
```
- 111_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-01.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file      
- traffic-reproducer-01.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Test timeline:
t=0s --> the first full minute after starting the traffic generator

- t=5-6s:   IPFIXv10 and NFv9 Templates, Option-Records and Data-Records sent
- t=10s:    nfacctd producing flow data to kafka

### Test execution and results:

Start the 2 traffic reproducers with provided configs. 

IMPORTANT: since we have multiple reproducer sending ipfix data, we need to make sure that both reproducers will send data within the same minute bucket. Since they both start sending data at mm:05, in order to ensure this we can simply avoid starting the reproducers if we are in the mm:00-mm:10 range within the minute.

When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka (t=10s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- No ERROR or WARN messages are present in the logfile
