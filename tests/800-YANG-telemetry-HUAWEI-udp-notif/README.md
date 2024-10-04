
## Test Description (800-YANG-telemetry-HUAWEI-udp-notif)

Yang Push Streaming Telemetry over UDP-notif transport from Huawei VRP node (see config below).

### OS version

Huawei Versatile Routing Platform Software
VRP (R) software, Version 8.231 (NE40E V800R023C10SPC306T)

### Provided files:
```
- 800_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic generator)
- traffic-reproducer-00.yml                 traffic replay function config file

- pmtelemetryd-00.conf                      pmtelemetryd daemon configuration file

- output-device-00.json                     desired pmtelemetryd kafka output [daisy.device_json topic] containing json messages
```

### Router Telemetry Configuration

<ipf-zbl1243-r-daisy-21>dis curr conf telemetry-ietf
...
  xpath /huawei-debug:debug/board-resouce-states/board-resouce-state
  xpath /huawei-debug:debug/cpu-infos/cpu-info
  xpath /huawei-debug:debug/memory-infos/memory-info
  xpath /huawei-ifm:ifm/interfaces/interface
  xpath /huawei-ifm:ifm/interfaces/interface/dynamic
  xpath /huawei-ifm:ifm/interfaces/interface/mib-statistics
  xpath /huawei-ifm:ifm/interfaces/interface/mib-statistics/huawei-pic:eth-port-err-sts
  xpath /huawei-network-instance:network-instance/instances/instance/huawei-l3vpn:afs/af/huawei-routing:routing/routing-manage/topologys/topology/routes/ipv4-prefix-statistics
  xpath /huawei-network-instance:network-instance/instances/instance/huawei-l3vpn:afs/af/huawei-routing:routing/routing-manage/topologys/topology/routes/ipv4-route-statistics/ipv4-route-statistic
  xpath /huawei-network-instance:network-instance/instances/instance/huawei-l3vpn:afs/af/huawei-routing:routing/routing-manage/topologys/topology/routes/ipv6-prefix-statistics
  xpath /huawei-network-instance:network-instance/instances/instance/huawei-l3vpn:afs/af/huawei-routing:routing/routing-manage/topologys/topology/routes/ipv6-route-statistics/ipv6-route-statistic

