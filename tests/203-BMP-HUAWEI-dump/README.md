## Test Description(203-BMP-HUAWEI-dump)

Test for verifying BMP regular dump feature. Pcap taken from test 200: Huawei VRP 8.210 (daisy-61 IETF lab) [with global and loc rib instance peers].

### Provided files:
```
- 203_test.py                  pytest file defining test execution

- traffic-00.pcap              pcap file (for traffic generator)
- traffic-reproducer-00.yml    traffic replay function config file

- nfacctd-00.conf              nfacctd daemon configuration file

- output-bmp-00.json           desired nfacctd kafka output [daisy.bmp topic] containing json messages
- output-bmp-dump-00.json      desired nfacctd kafka output [daisy.bmp.dump topic] containing json messages
- output-log-00.txt            log messages that need to be in the logfile
- output-log-01.txt            log messages that need to be in the logfile
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as arrays
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5s: BMP packets sent
- t=60s: BMP table dumped

### Test execution and results:

Part 1: Start traffic reproducer with provided config. 

IMPORTANT: do not kill the traffic reproducer process!

After reproducing all the packet, the traffic generator does not exit (thanks to keep_open: true in traffic-reproducer-00.yml ), and thus the TCP sockets with nfacctd thus remain open. 
Check the following:

- The nfacctd kafka output messages in topic daisy.bmp need to match with  the json messages in "output-bmp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- Excluding the ones present in the output-log-00.txt file, no additional ERROR or WARN messages are present in the logfile

Part 2: Now wait until the next BMP dump happens (configured every 60s). The dump event can be detected by looking for the log message in output-log-01.txt

Then check the following: 

- The nfacctd kafka output messages in topic daisy.bmp.dump need to match with  the json messages in "output-bmp-dump-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
