## Test Description (900-kafka-connection-loss)

Testing with kafka: losing kafka connection.

### Provided files:
```
- 900_test.py                               pytest file defining test execution

- traffic-reproducer-00.yml                 traffic replay function config file
- traffic-00.pcap                           pcap file (for traffic generator)

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-log-00.txt                         log messages that need to be in the logfile
- output-log-01.txt                         log messages that need to be in the logfile
```

### Test timeline:
t=0s --> the first full minute after starting the traffic generator

pcap traffic-00.pcap file time duration: 
- t=1s: NFv9 templates sent  
- t=6s: NFv9 data sent 

### Test execution and results:

1. Part 1: 

- start nfacctd and kafka normally
- check log messages in "output-log-00.txt" and verify that they are present in the logfile (order of appearence preserved, but there could/will be other logs in between) --> as long as this is successful you can proceed to part 2
- No ERROR or WARN messages are present in the logfile

2. Part 2:

- start traffic reproducer with provided config
- simulate kafka going down (e.g. stop kafka container)

After nfacctd attempts to produce to kafka, verify the following:

- Log messages in "output-log-01.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
