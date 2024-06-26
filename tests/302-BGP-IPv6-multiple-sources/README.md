## Test Description (302-BGP-IPv6-multiple-sources)

Testing with BGP traffic from 4 senders (mix ipv4 and ipv6), with 3 different source IPs. 2 senders have same IP and send the same BGP packets: pmacct will refuse the second connection. Testing also pretag with mix ipv4 and ipv6.

TODO DAISY: this test is not 100% (sometimes duplicated connection is not attempted) --> happening very rarely but still we should debug more...

### Provided files:
```
- 302_test.py                               pytest file defining test execution

- traffic-01.pcap                           pcap file (for traffic reproducer)
- traffic-02.pcap                           pcap file (for traffic reproducer)
- traffic-02.pcap                           pcap file (for traffic reproducer)
- traffic-03.pcap                           pcap file (for traffic reproducer)          --> same as traffic-02.pcap but with higher timestamp!
- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-reproducer-01.yml                 traffic replay function config file
- traffic-reproducer-02.yml                 traffic replay function config file
- traffic-reproducer-03.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips

- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages
- output-log-[00-04].txt                    log messages that need to be in the logfile
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

pcaps file time duration: 
- t=5-7s: BGP packets sent (from reproducers 00-02)
- t=20-22s: BGP packets sent (from reproducer 03)

### Test execution and results:

1. Part 1: start traffic reproducers (00, 01, 02, 03) with provided configs. 

IMPORTANT: Make sure that you **start the reproducers in the 25s-55s range of a minute**. This makes sure timings and interactions between the pcaps are respected in all scenarios! If both traffic reproducer would be started at e.g. mm:10s, then reproducer 03 would send packets in the minute bucket before the other 3, disrupting the test logic.
IMPORTANT: do not kill the traffic reproducer processes, which stay open thanks to keep_open=true!

Check the following at t=60s:

- The nfacctd kafka output messages in topic daisy.bgp need to match with  the json messages in "output-bgp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-[00-03].txt" are present in the logfile.
- HINT: ${repro_ip} and ${bgp_id} can be one of the 4 used by the reproducers!
- Excluding the ones present in the output-log-[00-03].txt file, no additional ERROR or WARN messages are present in the logfile

2. Part 2: 

Now kill the traffic reproducers (e.g. with CTRL-C). This will close the TCP sockets with nfacctd. 
Then check the following:

- Log messages in "output-log-04.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-04.txt file, no additional ERROR or WARN messages are present in the logfile