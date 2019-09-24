# Collecting BGP metrics with pmacct

Pmacct can export BGP updates and withdrawals received from a BGP or BMP (BGP Monitoring Protocol) peer (bmp_daemon_msglog, bgp_daemon_msglog) or dump the collected BGP RIB in regular intervals (bmp_table_dump,bgp_table_dump) from a BGP router.

This documents describes, dependent if they are collected through BGP or BMP, which metrics are collected with sample configurations for Apache Kafka export.

---
## BGP collected local RIB metrics

### pmacct example configuration
~~~~
bgp_daemon: true
bgp_daemon_ip: 192.0.2.1
bgp_daemon_port: 179
bgp_daemon_max_peers: 255
!
bgp_daemon_msglog_kafka_broker_host: kafka.example.com
bgp_daemon_msglog_kafka_broker_port: 9093
bgp_daemon_msglog_kafka_topic: topic.name.example.com
bgp_daemon_msglog_kafka_config_file: /etc/pmacct/librdkafka.conf
!
bgp_table_dump_kafka_broker_host: kafka.example.com
bgp_table_dump_kafka_broker_port: 9093
bgp_table_dump_kafka_topic: topic.name.example.com
bgp_table_dump_kafka_config_file: /etc/pmacct/librdkafka.conf
bgp_table_dump_refresh_time: 60
~~~~

### BGP metric description

Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`log_type` | pmacct log type. Either "update" or "delete" depending if BGP advertisement is an update or withdrawal
`timestamp` | pmacct time stamp of data collection
`peer_ip_src` | IP address of BGP router which peers to pmacct
`peer_tcp_port` | TCP port of BGP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`afi` | BGP Address Family Indicator (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`safi` | BGP Subsequent Address Family Identifier (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`ip_prefix` | BGP Prefix
`bgp_nexthop` | BGP next hop
`as_path` | BGP AS path
`comms` | BGP standard community string
`ecomms` | BGP extended community string
`origin` | BGP origin attribute
`local_pref` | BGP local preference
`rd` | BGP route-distinguisher
`label` | BGP MPLS VPN label
`writer_id` | pmacct process name and id

### Example BGP metrics
In case of table dump. Each batch of metric will start with "log_init" and end with "log_close" event_type meta data. This meta data includes the time of the data collection, the peering IP address and TCP port and which pmacct process name and id exported the metrics.
~~~~
{
  "seq": 1164,
  "timestamp": "1558677934.255773",
  "peer_ip_src": "192.0.2.2",
  "peer_tcp_port": 25344,
  "event_type": "log_init",
  "writer_id": "pmacct-bgp01c/4857"
}
{
  "seq": 1165,
  "log_type": "update",
  "timestamp": "1558677958.092808",
  "peer_ip_src": "192.0.2.2",
  "peer_tcp_port": 25344,
  "event_type": "log",
  "afi": 2,
  "safi": 128,
  "ip_prefix": "2001:db8::/32",
  "bgp_nexthop": "203.0.113.1",
  "as_path": "64496 64497",
  "comms": "64496:1 64497:2 64498:3",
  "ecomms": "RT:64496:100",
  "origin": "i",
  "local_pref": 0,
  "rd": "0:64499:1",
  "label": "25",
  "writer_id": "pmacct-bgp01c/4857"
}
{
  "seq": 1166,
  "timestamp": "1558677933.627806",
  "peer_ip_src": "192.0.2.2",
  "peer_tcp_port": 31402,
  "event_type": "log_close",
  "writer_id": "pmacct-bgp01c/4857"
}
~~~~

---
## BMP collected adjacent RIB in metrics

### pmacct example configuration
~~~~
bmp_daemon_ip: 192.0.2.1
bmp_daemon_port: 1790
bmp_daemon_max_peers: 255
bmp_daemon_msglog_kafka_broker_host: kafka.example.com
bmp_daemon_msglog_kafka_broker_port: 9093
bmp_daemon_msglog_kafka_topic: topic.name.example.com
bmp_daemon_msglog_kafka_config_file: /etc/pmacct/librdkafka.conf
~~~~

### BMP message type 0, route monitoring metrics
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`log_type` | pmacct log type. Either "update" or "delete" depending if BGP advertisement is an update or withdrawal
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "route_monitoring" for BMP message type 0
`peer_ip` | BGP peer IP address where BGP metrics are received from
`afi` | BGP Address Family Indicator (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`safi` | BGP Subsequent Address Family Identifier (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`ip_prefix` | BGP Prefix
`bgp_nexthop` | BGP next hop
`as_path` | BGP AS path
`comms` | BGP standard community string
`ecomms` | BGP extended community string
`origin` | BGP origin attribute
`local_pref` | BGP local preference
`rd` | BGP route-distinguisher
`label` | BGP MPLS VPN label

~~~~
{
  "seq": 5835,
  "log_type": "update",
  "timestamp": "2019-05-24 09:33:31.136734",
  "peer_ip": "192.0.2.2",
  "bmp_router_port": 45047,
  "event_type": "log",
  "afi": 1,
  "safi": 128,
  "ip_prefix": "198.51.100.0/24",
  "bgp_nexthop": "203.0.113.1",
  "as_path": "64496 64497 64498",
  "comms": "64496:1 64497:2 64498:3",
  "ecomms": "RT:64497:192",
  "origin": "i",
  "local_pref": 0,
  "rd": "0:64499:2",
  "label": "19356",
  "bmp_router": "192.0.2.2",
  "bmp_msg_type": "route_monitor"
}
~~~~

### BMP message type 1, statistics report
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "stats" for BMP message type 1
`peer_ip` | BGP peer IP address where BGP metrics are received from
`peer_asn` | BGP peer BGP AS number
`peer_type` | Type of BGP peer (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types)
`counter_type` | Statistics type field code (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#statistics-types)
`counter_type_str` | Statistics description
`counter_value` | Statistics counter value

~~~~
{
  "event_type": "log",
  "seq": 18271,
  "timestamp": "2019-05-24 09:41:34.543389",
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 45047,
  "bmp_msg_type": "stats",
  "peer_ip": "203.0.113.1",
  "peer_asn": 60633,
  "peer_type": 0,
  "counter_type": 0,
  "counter_type_str": "Number of prefixes rejected by inbound policy",
  "counter_value": 0
}
~~~~

### BMP message type 2, peer down
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "peer_down" for BMP message type 2
`peer_ip` | BGP peer IP address where BGP metrics are received from
`peer_asn` | BGP peer BGP AS number
`peer_type` | Type of BGP peer (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types)
`peer_type_str` | type of BGP peer description
`reason_type` | Reason type why BGP went down  (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-down-reason-codes)
`reason_str` | Reason description why BGP went down

~~~~
{
  "event_type": "log",
  "seq": 18696,
  "timestamp": "2019-05-24 09:49:22.437488",
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 45047,
  "bmp_msg_type": "peer_down",
  "peer_ip": "203.0.113.3",
  "peer_asn": 64496,
  "peer_type": 0,
  "peer_type_str": "Global Instance Peer",
  "reason_type": 1,
  "reason_str": "The local system closed the session"
}
~~~~

### BMP message type 3, peer up
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "peer_up" for BMP message type 3
`peer_ip` | BGP peer IP address where BGP metrics are received from
`peer_asn` | BGP peer BGP AS number
`peer_type` | Type of BGP peer (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types)
`peer_type_str` | type of BGP peer description
`bgp_id` | BGP router ID of remote peer from BGP open message
`local_port` | BGP peer local TCP port
`remote_port` | BGP peer remote TCP port
`local_ip` | BGP peer local IP address

~~~~
{
  "event_type": "log",
  "seq": 10,
  "timestamp": "2019-05-24 09:31:03.160056",
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 45047,
  "bmp_msg_type": "peer_up",
  "peer_ip": "203.0.113.2",
  "peer_asn": 64496,
  "peer_type": 0,
  "peer_type_str": "Global Instance Peer",
  "bgp_id": "192.0.2.2",
  "local_port": 26354,
  "remote_port": 179,
  "local_ip": "203.0.113.1"
}
~~~~

### BMP message type 4, initiation
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "init" for BMP message type 4
`bmp_init_info_sysdescr` | BGP software version of router peering to pmacct
`bmp_init_info_sysname` | BGP hostname of router peering to pmacct
`writer_id` | pmacct process name and id
 
~~~~
{
  "event_type": "log",
  "seq": 9,
  "timestamp": "2019-06-01 18:29:58.515420",
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 17677,
  "bmp_msg_type": "init",
  "bmp_init_info_sysdescr": "6.5.2",
  "bmp_init_info_sysname": "bgprouter.example.com",
  "writer_id": "daisy62bmp01c/9254"
}
~~~~