## Test Description (502-IPFIXv10-BGP-IPv6-CISCO-SRv6-lcomms)

IPFIX and BGP from IOS XR 7.10.1 with IPv6 transport. BGP with standard, large and extended comms configured.

### Provided files:
```
- 502_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages
```

### Scenarios

- Default scenario: comms, ecomms, lcomms, as_path, ... are encoded as array
- Scenario-01: comms, ecomms, lcomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:     BGP messages sent  
- t=7-8s      IPFIXv10 Templates, Option-Records and Data-Records sent
- t=15s:      nfacctd producing flow data to kafka

### Test execution and results:

After reproducing all the packet, the traffic generator does not exit (thanks to keep_open: true in traffic-reproducer-00.yml ), and thus the TCP sockets with nfacctd thus remain open. 
After nfacctd produced to kafka (t=15s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The nfacctd kafka output messages in topic daisy.bgp need to match with  the json messages in "output-bgp-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_start and timestamp_end, which come from IPFIX fields and will stay the same.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- No ERROR or WARN messages are present in the logfile
