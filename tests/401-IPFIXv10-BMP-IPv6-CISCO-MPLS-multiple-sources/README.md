## Test Description (401-IPFIXv10-BMP-IPv6-CISCO-MPLS)

IPFIX v10 + BMP with IPV6 transport from CISCO IOS XR 7.10.1. BMP glob-instance and loc-rib.

### Provided files:
```
- 401_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-01.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic] containing json messages
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as array
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:     [Peer 1] BMP messages sent  
- t=6-7s      [Peer 1] IPFIXv10 Templates, Option-Records and Data-Records sent
- t=10-11s:   [Peer 2] BMP messages sent  
- t=11-12s    [Peer 2] IPFIXv10 Templates, Option-Records and Data-Records sent
- t=30s:      nfacctd producing flow data to kafka

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka (t=30s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The nfacctd kafka output messages in topic daisy.bmp need to match with  the json messages in "output-bmp-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_start and timestamp_end, which come from IPFIX fields and will stay the same.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- No ERROR or WARN messages are present in the logfile
