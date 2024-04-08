## Test Description (500-IPFIXv10-BGP-CISCO-SRv6)

BGP and IPFIX v10 from CISCO IOS XR 7.8.2 with data [260,340,342] and options [256,257,334,338].

- MPLS VPN RD from option 334
- Sampling info from option 257
- IF_Name from option 256

### Provided files:
```
- 500_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages [before closing socket]
- output-bgp-01.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages [after closing socket]
- output-log-00.txt                         log messages that need to be in the logfile [before closing socket]
- output-log-01.txt                         log messages that need to be in the logfile [after closing socket]
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as array
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings
- Scenario-02: BGP HA enabled (to ensure single daemon works correclty when started in HA mode but redis not available)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:     BGP messages sent  
- t=7-8s      IPFIXv10 Templates, Option-Records and Data-Records sent
- t=15s:      nfacctd producing flow data to kafka

### Test execution and results:

1. Part 1: start traffic reproducer with provided config. 

IMPORTANT: do not kill the traffic reproducer process!

After reproducing all the packet, the traffic generator does not exit (thanks to keep_open: true in traffic-reproducer-00.yml ), and thus the TCP sockets with nfacctd thus remain open. 
After nfacctd produced to kafka (t=15s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The nfacctd kafka output messages in topic daisy.bgp need to match with  the json messages in "output-bgp-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_start and timestamp_end, which come from IPFIX fields and will stay the same.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- No ERROR or WARN messages are present in the logfile

2. Part 2: 

Now kill the traffic reproducer (e.g. with CTRL-C). This will close the TCP sockets with nfacctd. 
Then check the following:

- The (new) nfacctd kafka output messages in topic daisy.bgp need to match with the json messages in "output-bgp-01.json".
- Log messages in "output-log-01.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-01.txt file, no additional ERROR or WARN messages are present in the logfile