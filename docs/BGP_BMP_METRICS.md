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
`as_path_id` | BGP ADD-Path attribute (https://tools.ietf.org/html/rfc7911#section-3)
`aigp` | BGP AIGP attribute (https://tools.ietf.org/html/rfc7311#section-3)
`psid_li` | BGP Prefix-SID Label Index attribute (https://tools.ietf.org/html/rfc8669#section-3.1)
`writer_id` | pmacct process name and id

### Example BGP metrics
In case of table dump. Each batch of metric will start with "log_init" and end with "log_close" event_type meta data. This meta data includes the time of the data collection, the peering IP address and TCP port and which pmacct process name and id exported the metrics.
~~~~
{
  "seq": 1161,
  "timestamp": "2020-06-13 14:11:38.515220",
  "peer_ip_src": "192.0.2.2",
  "peer_tcp_port": 25344,
  "event_type": "log_init",
  "writer_id": "pmacct-bgp01c/4852"
}
{
  "seq": 1162,
  "log_type": "update",
  "timestamp": "2020-06-13 14:11:39.092808",
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
  "seq": 1163,
  "timestamp": "2020-06-13 14:11:39.627806",
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
`is_out` | Boolean, if present and true it indicates data from Adj-Rib-Out
`is_post` | Boolean, if present and true it indicates post-policy data (in conjunction with is_in, is_out) 
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
`as_path_id` | BGP ADD-Path attribute (https://tools.ietf.org/html/rfc7911#section-3)
`aigp` | BGP AIGP attribute (https://tools.ietf.org/html/rfc7311#section-3)
`psid_li` | BGP Prefix-SID Label Index attribute (https://tools.ietf.org/html/rfc8669#section-3.1)
`bmp_rm_info_0` | BMP path marking (https://tools.ietf.org/html/draft-cppy-grow-bmp-path-marking-tlv-03#section-3)

~~~~
{
  "seq": 6399,
  "log_type": "update",
  "timestamp": "2020-05-24T14:34:04.000000+02:00",
  "is_post": 0,
  "is_out": 1,
  "bmp_rm_info_0": "00-01-00-01-00-06-00-00-00-00-00-00",
  "peer_ip": "198.51.100.72",
  "peer_tcp_port": 0,
  "event_type": "log",
  "afi": 1,
  "safi": 128,
  "ip_prefix": "203.0.113.70/32",
  "bgp_nexthop": "198.51.100.62",
  "as_path": "65538 65000",
  "comms": "64496:20 64496:1001 64496:1033 64497:3 64499:70 64499:100",
  "ecomms": "RT:64497:32",
  "origin": "i",
  "local_pref": 0,
  "rd": "0:64499:72",
  "label": "1048575",
  "bmp_router": "192.0.2.52",
  "bmp_router_port": 60720,
  "bmp_msg_type": "route_monitor"
}
~~~~

### BMP message type 1, statistics report
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`is_loc` | Boolean, if present and true it indicates data from Loc-Rib
`is_filtered` | Boolean, if present and true it indicates filtered data (in conjunction with is_loc)
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "stats" for BMP message type 1
`peer_ip` | BGP peer IP address where BGP metrics are received from
`peer_asn` | BGP peer BGP AS number
`peer_type` | Type of BGP peer (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types)
`rd` | BGP peer route-distinguisher (https://tools.ietf.org/html/rfc7854#section-4.2)
`counter_type` | Statistics type field code (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#statistics-types)
`counter_type_str` | Statistics description
`counter_value` | Statistics counter value

~~~~
{
  "event_type": "log",
  "seq": 18271,
  "timestamp": "2019-05-24 09:41:34.543389",
  "is_filtered": 0,
  "is_in": 1,
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 45047,
  "bmp_msg_type": "stats",
  "peer_ip": "203.0.113.1",
  "peer_asn": 60633,
  "peer_type": 0,
  "rd": "0:64499:2",
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
`rd` | BGP peer route-distinguisher (https://tools.ietf.org/html/rfc7854#section-4.2)
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
  "rd": "0:64499:2",
  "reason_type": 1,
  "reason_str": "The local system closed the session"
}
~~~~

### BMP message type 3, peer up
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`is_in` | Boolean, if present and true it indicates data from Adj-Rib-In
`is_post` | Boolean, if present and true it indicates post-policy data (in conjunction with is_in, is_out)
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "peer_up" for BMP message type 3
`peer_ip` | BGP peer IP address where BGP metrics are received from
`peer_asn` | BGP peer BGP AS number
`peer_type` | Type of BGP peer (https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml#peer-types)
`peer_type_str` | type of BGP peer description
`rd` | BGP peer route-distinguisher (https://tools.ietf.org/html/rfc7854#section-4.2)
`bgp_id` | BGP router ID of remote peer from BGP open message
`local_port` | BGP peer local TCP port
`remote_port` | BGP peer remote TCP port
`local_ip` | BGP peer local IP address

~~~~
{
  "event_type": "log",
  "seq": 10,
  "timestamp": "2019-05-24 09:31:03.160056",
  "is_post": 1,
  "is_in": 1,
  "bmp_router": "192.0.2.2",
  "bmp_router_port": 45047,
  "bmp_msg_type": "peer_up",
  "peer_ip": "203.0.113.2",
  "peer_asn": 64496,
  "peer_type": 0,
  "peer_type_str": "Global Instance Peer",
  "rd": "0:64499:2",
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

### BMP message type 5, termination
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "term" for BMP message type 5
`bmp_term_info_reason` | BMP termination reason
`writer_id` | pmacct process name and id
 
~~~~
{
  "event_type": "log",
  "seq": 6432,
  "timestamp": "2020-05-24T14:36:19.744818+02:00",
  "bmp_router": "192.0.2.52",
  "bmp_router_port": 60720,
  "bmp_msg_type": "term",
  "bmp_term_info_reason": "Session administratively closed"
}

~~~~

### BMP message type TBD, Route Policy and Attribute Trace
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | pmacct time stamp of data collection
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "rpat" for BMP message type 6
`rd` | BGP route-distinguisher
`prefix` | BGP prefix
`prefix_len` | BGP prefix mask
`bgp_id` | BGP router-id
`afi` | BGP Address Family Indicator (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`safi` | BGP Subsequent Address Family Identifier (RFC 4760 -  Multiprotocol Extensions for BGP-4)
`bmp_rpat_info_0` | VRF Name and ID (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.1)
`bmp_rpat_info_1` | Route-Policy (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`bmp_rpat_info_2` | Pre Route-Policy (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.3)
`bmp_rpat_info_3` | Post Route-Policy (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.4)
`bmp_rpat_info_4` | String (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.5)
`writer_id` | pmacct process name and id
 
~~~~
{
  "event_type": "log",
  "seq": 360,
  "timestamp": "2020-03-27T12:45:59.473293+01:00",
  "bmp_router": "192.0.2.52",
  "bmp_router_port": 49531,
  "bmp_msg_type": "rpat",
  "rd": "0:64499:12",
  "prefix": "203.0.113.30",
  "prefix_len": 32,
  "bgp_id": "192.0.2.82",
  "afi": 1,
  "safi": 128,
  "bmp_rpat_info_0": "00-00-00-00-5F-70-75-62-6C-69-63-5F",
  "bmp_rpat_info_1": "C0-01-01-00-00-00-00-00-00-00-00-00-00-00-00-C6-33-64-47-C0-00-02-47-00-01-00-03-00-09-56-50-4E-5F-4F-55-54-32-30-00-02-32-30-00",
  "bmp_rpat_info_2": "40-01-01-00-40-02-0A-02-02-00-01-00-06-00-00-FD-E8-40-03-04-C6-33-64-52-C0-08-14-FB-F0-01-2B-FB-F0-03-E9-FB-F0-04-0A-FB-F1-00-01-FB-F3-00-1E-C0-10-08-00-02-FB-F1-00-00-00-0B",
  "bmp_rpat_info_3": "",
  "bmp_rpat_info_4": "78-6D-6C-6E-73-3A-72-74-70-3D-22-75-72-6E-3A-68-75-61-77-65-69-3A-79-61-6E-67-3A-68-75-61-77-65-69-2D-72-6F-75-74-69-6E-67-2D-70-6F-6C-69-63-79-22-20-73-65-6C-65-63-74-3D-22-2F-72-74-70-3A-72-6F-75-74-69-6E-67-2D-70-6F-6C-69-63-79-2F-72-74-70-3A-70-6F-6C-69-63-79-2D-64-65-66-69-6E-69-74-69-6F-6E-73-2F-72-74-70-3A-70-6F-6C-69-63-79-2D-64-65-66-69-6E-69-74-69-6F-6E-5B-72-74-70-3A-6E-61-6D-65-3D-27-56-50-4E-5F-4F-55-54-32-30-27-5D-2F-72-74-70-3A-6E-6F-64-65-73-2F-72-74-70-3A-6E-6F-64-65-5B-72-74-70-3A-73-65-71-75-65-6E-63-65-3D-27-32-30-27-5D-00"
  "writer_id": "daisy62bmp01c/9254"
}
~~~~
