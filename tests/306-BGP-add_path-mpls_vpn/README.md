## Test Description (306-BGP-add_path-mpls_vpn)

Test for the ADD-PATH NLRI parsing for labeled-unicast and MPLS-VPN SAFIs on BGP.

### Provided files:
```
- 306_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd
                                            HINT: IPs need to match with repro_ips

- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic]
                                            containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
                                            (includes the extra "Capability: ADD-PATHs" log line)
```

### Test timeline:

t=0s --> traffic-reproducer startup-time

- t=5-6s: BGP packets sent

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages,
the traffic reproducer will exit automatically (keep_open=false).

After nfacctd produced to kafka, check the following:
- The nfacctd kafka output messages in topic daisy.bgp need to match with the json messages
  in "output-bgp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers
  when comparing the json output!).
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved,
  but there could/will be other logs in between).
- Excluding the ones present in the output-log-00.txt file, no additional ERROR or WARN messages
  are present in the logfile.
