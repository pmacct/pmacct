## Test Description (102-NFv9-CISCO-f2rd-pretag-sampling-reload)

NetFlow v9 from CISCO ASR9k IOS XR with IPFIX data only (templates 260,313) from 2 different source_ID/observation_ID.

f2rd_map is used to set MPLS VPN RD. Pretag map is used as well. Map reload is also tested.

### Provided files:
```
- 102_test.py                             pytest file defining test execution

- traffic-00.pcap                         pcap file (for traffic generator)
- traffic-reproducer-00.yml               traffic replay function config file

- nfacctd-00.conf                         nfacctd daemon configuration file

- pmacct_mount/pretag-00.map              pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/f2rd-00.map                flow_to_rd mapping file for nfacctd          HINT: IPs need to match with repro_ips
- pmacct_mount/sampling-00.map            sampling mapping file for nfacctd            HINT: IPs need to match with repro_ips
- pmacct_mount/custom-primitives-00.map   list of custom primitives for nfacctd

- pmacct_mount/pretag-01.map              [for reload] pretag mapping file for nfacctd              HINT: IPs need to match with repro_ips
- pmacct_mount/f2rd-01.map                [for reload] flow_to_rd mapping file for nfacctd          HINT: IPs need to match with repro_ips
- pmacct_mount/sampling-01.map            [for reload] sampling mapping file for nfacctd            HINT: IPs need to match with repro_ips

- output-flow-00.json                     desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-log-00.txt                       log messages that need to be in the logfile
- output-flow-01.json                     desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-log-01.txt                       log messages that need to be in the logfile
```

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:   NFv9 Data-Template and Data-Records sent
- t=10s:    nfacctd producing flow data to kafka

### Test execution and results:

1. Part 1: start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false).
After nfacctd produced to kafka (t=10s), check the following:

- The nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-00.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- No ERROR or WARN messages are present in the logfile

2. Reloading maps

- First replace the maps files with pretag-01.map, sampling-01.map, and f2rd-01.map
- Now you can trigger map reload on nfacctd using signals:
        
      kill -SIGUSR2 <nfacctd-proc-id>

3. Part 3: start traffic reproducer again with the same config
After nfacctd produced again to kafka, check the following:

- The (new) nfacctd kafka output messages in topic daisy.flow need to match with the json messages in "output-flow-01.json".
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- Log messages (new) in "output-log-01.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- No ERROR or WARN messages are present in the logfile