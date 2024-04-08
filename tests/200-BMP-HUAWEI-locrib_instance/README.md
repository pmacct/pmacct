## Test Description(200-BMP-HUAWEI-locrib_instance)

BMP test with pcap from Huawei VRP 8.210 (daisy-61 IETF lab) [with global and loc rib instance peers].

### Provided files:
```
- 200_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips

- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic] containing json messages
- output-log-00.txt                         log messages that need to be in the logfile
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as arrays
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> traffic-reproducer startup-time

- t=5s: BMP packets sent 

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka, check the following:

- The nfacctd kafka output messages in topic daisy.bmp need to match with  the json messages in "output-bmp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-00.txt file, no additional ERROR or WARN messages are present in the logfile
