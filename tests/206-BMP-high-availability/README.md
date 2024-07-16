## Test Description(206-BMP-high-availability)

The purpose of this test is to verify the BMP High-Availability feature in pmacct ([README](https://github.com/pmacct/pmacct/blob/master/docs/README_BGP_BMP_HA.md)).
Traffic taken from test 205 (only a subset and timestamps adjusted and messages rearranged with smaller MTU).

### Provided files:
```
- 206_test.py                  pytest file defining test execution

- traffic-00.pcap              pcap file 1 (for traffic generator)
- traffic-reproducer-00.yml    traffic replay function config file

- nfacctd-00.conf              nfacctd daemon configuration file

- output-bmp-00.json           desired nfacctd kafka output [daisy.bmp topic] containing json messages
```

### Scenarios

- Default scenario: cdada queue max size 1000 messages (retention time, 15s)
- Scenario-01: cdada queue max size unlimited (only limited by retention time, 15s)
- Scenario-02: cdada queue max size unlimited (only limited by retention time, 10s)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5s: BMP Init
- t=7-16s: BMP PeerUp
- t=16-45s: BMP Route Monitoring 
- t=45-48: BMP Stats
