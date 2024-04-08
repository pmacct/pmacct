## Test Description (402-IPFIXv10-BMP-IPv6-high-availability)

IPFIX v10 + BMP with IPV6 transport from CISCO IOS XR 7.10.1. BMP glob-instance and loc-rib.
The purpose of this test is to verify the BMP High-Availability feature in pmacct ([README](https://github.com/pmacct/pmacct/blob/master/docs/README_BGP_BMP_HA.md)).
With this test we make sure that the stand-by daemon is able to correclty correlate and produce flow information like the active one.

### Provided files:
```
- 402_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file
- container-setup.yml                       traffic reproducer container config file

- nfacctd-00.conf                           nfacctd daemon configuration file

- pmacct_mount/pretag-00.map                pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map     list of custom primitives for nfacctd

- output-flow-00.json                       desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-bmp-00.json                        desired nfacctd kafka output [daisy.bmp topic] containing json messages
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-9s:     BMP messages sent  
- t=24-30s    IPFIXv10 Templates, Option-Records and Data-Records sent
- t=60s:      nfacctd daemons producing flow data to kafka
