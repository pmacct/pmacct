## Test Description (110-IPFIXv10-NFv9-multiple-sources)

Test with ipfix only from 3 different source IPs (pcaps from tests 100, 101 and 102).

### Provided files:
```
- 110_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file 1 (for traffic generator)
- traffic-01.pcap                           pcap file 2 (for traffic generator)
- traffic-02.pcap                           pcap file 3 (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file
- traffic-reproducer-02.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:   IPFIXv10 and NFv9 Templates, Option-Records and Data-Records sent
- t=10s:    nfacctd producing flow data to kafka

(refer to tests 100, 101, 102 for pcap contents)

### Test execution and results:

Start the 3 traffic reproducers with provided configs. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka (t=10s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- No ERROR or WARN messages are present in the logfile
