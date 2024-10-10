
## Test Description (801-YANG-telemetry-IPv6-CISCO-tcp-json)

Yang Streaming Telemetry over proprietary tcp-json transport from Cisco IOS XR node (see config below).

### OS version

Cisco IOS XR Software, Version 24.4.1.101S
Copyright (c) 2013-2024 by Cisco Systems, Inc.

### Provided files:
```
- 801_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- pmtelemetryd-00.conf                      pmtelemetryd daemon configuration file

- output-device-00.json                     desired pmtelemetryd kafka output [daisy.device_json topic] containing json messages
```

### Router Telemetry Configuration

RP/0/RP0/CPU0:ipf-zbl1327-r-daisy-90#sho run telemetry model-driven 
...
  sensor-path openconfig-platform:components
  sensor-path openconfig-interfaces:interfaces
  sensor-path Cisco-IOS-XR-mpls-lsd-oper:mpls-lsd/label-range
  sensor-path Cisco-IOS-XR-sysadmin-asr9k-envmon-ui:environment/oper
  sensor-path Cisco-IOS-XR-wdsysmon-fd-oper:system-monitoring/cpu-utilization
  sensor-path Cisco-IOS-XR-nto-misc-oper:memory-summary/nodes/node/summary
  sensor-path Cisco-IOS-XR-asr9k-lpts-oper:platform-lptsp-ifib-static/node-statics
  sensor-path Cisco-IOS-XR-mpls-lsd-oper:mpls-lsd-nodes/mpls-lsd-node/label-summary
  sensor-path Cisco-IOS-XR-procmem-oper:processes-memory/nodes/node/process-ids/process-id
  sensor-path Cisco-IOS-XR-asr9k-np-oper:hardware-module-np/nodes/node/nps/np/counters/np-counter
 !