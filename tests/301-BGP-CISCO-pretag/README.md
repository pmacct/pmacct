## Test Description (301-BGP-pmbgpd-CISCO-pretag)

IMPORTANT: for this test we use the pmbgpd daemon (not nfacctd)!

Testing with BGP ipv4 traffic with RD, comms, ecomms, AS_path. Testing also pretag.

### Provided files:
```
- 301_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- pmbgpd-00.conf                            pmbgpd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for pmbgpd              HINT: IPs need to match with repro_ips

- output-bgp-00.json                        desired pmbgpd kafka output [daisy.bgp topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as arrays
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> traffic-reproducer startup-time

- t=5-6s: BGP packets sent 

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After pmbgpd produced to kafka, check the following:

- The pmbgpd kafka output messages in topic daisy.bgp need to match with  the json messages in "output-bgp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-00.txt file, no additional ERROR or WARN messages are present in the logfile
