## Test Description (209-BMP-add_path-mpls_vpn)

Test for the ADD-PATH NLRI parsing for labeled-unicast and MPLS-VPN SAFIs on BMP.

### Provided files:
```
- 209_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic]
                                            containing json messages
```

### Test execution and results:

Start traffic reproducer with provided config. After reproducing all the packets, the traffic
generator does not exit (keep_open: true), so the TCP socket with nfacctd remains open.

Check the following:
- The nfacctd kafka output messages in topic daisy.bmp need to match the json messages
  in "output-bmp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (ignore sequence numbers when comparing).
- No ERROR or WARN messages are present in the logfile.
