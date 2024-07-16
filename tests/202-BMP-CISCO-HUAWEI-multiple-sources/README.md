## Test Description (202-BMP-pmbmpd-CISCO-HUAWEI-multiple-sources)

IMPORTANT: for this test we use the pmbmpd daemon (not nfacctd)!

Testing with BMP traffic from 3 different source IPs.

### Provided files:
```
- 202_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file 1 (for traffic generator)
- traffic-01.pcap                           pcap file 2 (for traffic generator)
- traffic-02.pcap                           pcap file 3 (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file
- traffic-reproducer-02.yml                 traffic replay function config file

- pmbmpd-00.conf                            pmbmpd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for pmbmpd              HINT: IPs need to match with repro_ips

- output-bmp-00.json                        desired pmbmpd kafka output [daisy.bmp topic] containing json messages [before closing sockets]
- output-log-00.txt                         log messages that need to be in the logfile [before closing sockets]
- output-log-01.txt                         log messages that need to be in the logfile [after closing socket] 
```

### Scenarios

- Default scenario: pmbmpd with basic configuration
- Scenario-01: BMP HA enabled (to ensure single daemon works correclty when started in HA mode but redis not available)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-13s: BMP packets sent 

### Test execution and results:

1. Part 1: start traffic reproducers (00, 01, 02) with provided configs. 

IMPORTANT: do not kill the traffic reproducer processes!

After reproducing all the packet, the traffic generators do not exit (thanks to keep_open: true), and thus the TCP sockets with nfacctd thus remain open. Check the following:

- The pmbmpd kafka output messages in topic daisy.bmp need to match with the json messages in "output-bmp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- HINT: for this specific test, as the traffic reproducers are started concurrently, the order of the logs messages for the 3 ${repro_ip} could change. Important is that all 3 repro_ips are there in the logs, no matter for which peer number.
- Excluding the ones present in the output-log-00.txt file, no additional ERROR or WARN messages are present in the logfile

2. Part 2: 

Now kill the traffic reproducer (e.g. with CTRL-C). This will close the TCP sockets with nfacctd. 
Then check the following:

- Log messages in "output-log-01.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-01.txt file, no additional ERROR or WARN messages are present in the logfile
