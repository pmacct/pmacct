## Test Description(205-BMP-6wind-FRR-peer_down)

Test with BMP peer-up, route-monitoring, stats and peer-down messages from 6wind PE router (FRR-based router).
TODO: regenerate new pcap for this test with updated FRR release (contains invalid BMP data)

### Provided files:
```
- 205_test.py                  pytest file defining test execution

- traffic-00.pcap              pcap file 1 (for traffic generator)
- traffic-reproducer-00.yml    traffic replay function config file

- nfacctd-00.conf              nfacctd daemon configuration file

- output-bmp-00.json           desired nfacctd kafka output [daisy.bmp topic] containing json messages
```

### Scenarios

- Default scenario: comms, ecomms, as_path, ... are encoded as arrays
- Scenario-01: comms, ecomms, as_path, ... are encoded as strings

### Test timeline:

t=0s --> traffic-reproducer startup-time

- t=5s: BMP Init
- t=7-8s: BMP PeerUp and RouteMonitoring messages (with Updates)
- t=7-8s: BMP Stats
- t=12-13s: BMP PeerDown
        --> peer 203.0.113.44 going down
- t=14-15s: BMP PeerUp and RouteMonitoring
        --> peer 203.0.113.44 coming back up
- t=19-20s: BMP PeerDown
        --> peer 203.0.113.44 going down
- t=21-22s: BMP PeerUp and RouteMonitoring
        --> peer 203.0.113.44 coming back up
- t=21-22s: BMP Stats

### Test execution and results:

Part 1: Start traffic reproducer with provided config. 

After reproducing all the packet, the traffic generator does not exit (thanks to keep_open: true in traffic-reproducer-00.yml ), and thus the TCP sockets with nfacctd thus remain open. 
Check the following:

- The nfacctd kafka output messages in topic daisy.bmp need to match with  the json messages in "output-bmp-00.json".
- The timestamp values will change between runs.
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- No ERR or WARN messages are present in the logfile
