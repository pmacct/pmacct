## Test Description (103-IPFIXv10-CISCO-pretag-JSON_encoding)

Testing producing to kafka with JSON instead of avro encoding.

Otherwise this is the same test as 100: IPFIX v10 from CISCO ASR9k IOS XR 7.5.2 with IPFIX data only (templates 260 and 261).

### Provided files:
```
- 103_test.py                  pytest file defining test execution

- traffic-00.pcap              pcap file (for traffic generator)
- traffic-reproducer-00.yml    traffic replay function config file

- nfacctd-00.conf              nfacctd daemon configuration file

- output-flow-00.json          desired nfacctd kafka output [daisy.flow topic] containing json messages
- output-log-00.txt            log messages that need to be in the logfile
```

### Scenarios

- Default scenario produces **json** output with a simple aggregate (no maps)
- Scenario-01 produces **json** output with pretag map (label, default encoding)
- Scenario-02 produces **json** output with pretag map (label, **encoded as map**)
- Scenario-03 produces **avro** output with pretag map (label, default encoding)
- Scenario-04 produces **avro** output with pretag map (label, **encoded as map**)
- Scenario-05 produces **avro** output with pretag map (longer label, **encoded as map**)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5-6s:   IPFIX Data-Template and Data-Records sent
- t=10s:    nfacctd producing flow data to kafka

### Test execution and results:

Start traffic reproducer with provided config. When finished producing messages, the traffic reproducer will exit automatically (keep_open=false). 
After nfacctd produced to kafka (t=10s), check the following:

- The nfacctd kafka output messages in topic daisy.flow_json need to match with the json messages in "output-flow-00.json". 
- The timestamp values will change between runs, with the only exceptions being timestamp_export, timestamp_start, and timestamp_end, which come from IPFIX/NFv9 fields and will stay the same.
- Order of the json messages could change
- Log messages in "output-log-00.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
- No ERROR or WARN messages are present in the logfile
