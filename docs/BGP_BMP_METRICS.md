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
`timestamp` | time stamp when data was generated on router
`timestamp` | time stamp of BMP data export
`bmp_router` | IP address of BMP router which peers to pmacct
`bmp_router_port` | TCP port of BMP router which peers to pmacct
`event_type` | pmacct event type. Can be either "log" for msglog or "dump" for table_dump.
`bmp_msg_type` | "route_monitoring" for BMP message type 0
`path_status` | BMP path-marking status https://tools.ietf.org/html/draft-cppy-grow-bmp-path-marking-tlv#section-2.1
`reason_code` | BMP path-marking reason_code https://tools.ietf.org/html/draft-cppy-grow-bmp-path-marking-tlv#section-2.1
`is_in' | Boolean, if present and true it indicates data from Local-RIB
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

~~~~
{
  "seq": 67938379,
  "log_type": "update",
  "timestamp": "2020-12-17T11:54:54.000000+01:00",
  "timestamp_arrival": "2020-12-17T11:54:55.000000",
  "is_post": 1,
  "is_in": 1,
  "rd": "0:64499:82",
  "path_status": [
    "Non-selected",
    "Backup"
  ],
  "reason_code": "0x0014",
  "peer_ip": "192.0.32.154",
  "is_post": 0,
  "is_out": 1,
  "peer_ip": "198.51.100.72",
  "peer_tcp_port": 0,
  "event_type": "log",
  "afi": 1,
  "safi": 1,
  "ip_prefix": "203.0.113.82/32",
  "bgp_nexthop": "192.0.32.154",
  "as_path": "65000 65539",
  "comms": "64496:299 64496:1001 64496:1033 64497:3 64499:81",
  "ecomms": "SoO:64497:63",
  "origin": "i",
  "local_pref": 0,
  "timestamp_arrival": "2020-12-17T11:54:56.005522+01:00",
  "bmp_router": "192.0.2.72",
  "bmp_router_port": 52306,
  "bmp_msg_type": "route_monitor",
  "writer_id": "ietfint_nfacctd-bmp01_c/1958020"
}
~~~~

### BMP message type 1, statistics report
Title | Description
:----- | :-----------
`seq` | pmacct sequence number. Uniquely identifies each metric.
`timestamp` | time stamp of BMP data export
`timestamp_arrival` | pmacct time stamp of data collection
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
  "timestamp": "2020-12-17T11:53:37.539446+01:00",
  "timestamp_arrival": "2020-12-17T11:53:37.669796+01:00",
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
`timestamp` | time stamp of BMP data export
`timestamp_arrival` | pmacct time stamp of data collection
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
  "timestamp": "2020-12-17T11:53:37.539446+01:00",
  "timestamp_arrival": "2020-12-17T11:53:37.669796+01:00",
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
`timestamp` | time stamp of BMP data export
`timestamp_arrival` | pmacct time stamp of data collection
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
  "timestamp": "2020-12-17T11:53:37.539446+01:00",
  "timestamp_arrival": "2020-12-17T11:53:37.669796+01:00",
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
`timestamp` | unsupported - zeroed out
`timestamp_arrival` | pmacct time stamp of data collection
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
  "timestamp": "0000-00-00 00:00:00.000000",
  "timestamp_arrival": "2020-12-17T11:53:37.669796+01:00",
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
`timestamp` | unsupported - zeroed out
`timestamp_arrival` | pmacct time stamp of data collection
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
  "timestamp": "0000-00-00 00:00:00.000000",
  "timestamp_arrival": "2020-12-17T11:53:37.669796+01:00",
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
`timestamp` | time stamp of BMP data export
`timestamp_arrival` | pmacct time stamp of data collection
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
`vrf_id` | VRF identifier (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.1)
`vrf_name` | VRF name string (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.1)
`policy_is_match` | route-policy matched (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_is_permit` | route-policy permitted (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_is_diff` | route-policy modified (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_is_class` | route-policy type (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_name` | route-policy name (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_id` | route-policy sequence id (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`policy_nf` | next route-policy is chained (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.2)
`bmp_rpat_info_pre_policy_attr` | Pre Route-Policy (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.3)
`bmp_rpat_info_post_policy_attr` | Post Route-Policy (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.4)
`bmp_rpat_info_strin` | String (https://tools.ietf.org/html/draft-xu-grow-bmp-route-policy-attr-trace#section-2.3.5)
`writer_id` | pmacct process name and id
 
~~~~
{
  "event_type": "log",
  "seq": 68222721,
  "timestamp": "2020-12-17T12:09:42.275678+01:00",
  "timestamp_arrival": "2020-12-17T12:09:44.285191+01:00",
  "bmp_router": "192.0.2.72",
  "bmp_router_port": 52306,
  "seq": 360,
  "bmp_router": "192.0.2.52",
  "bmp_router_port": 49531,
  "bmp_msg_type": "rpat",
  "rd": "0:64499:82",
  "prefix": "203.0.113.72",
  "prefix_len": 32,
  "bgp_id": "192.0.32.155",
  "afi": 1,
  "safi": 1,
  "vrf_id": 3,
  "vrf_name": "C20",
  "policy_is_match": 1,
  "policy_is_permit": 1,
  "policy_is_diff": 0,
  "policy_class": "Inbound policy",
  "peer_bgp_id": "198.51.100.55",
  "peer_ip": "192.0.32.155",
  "peer_asn": 65000,
  "policy_name": [
    "RP-C20-IP-IN"
  ],
  "policy_id": [
    "10"
  ],
  "policy_nf": [
    null
  ],
  "bmp_rpat_info_pre_policy_attr": "40-01-01-00-40-02-12-02-04-00-00-FD-E8-00-01-00-03-00-01-00-00-00-01-00-01-40-03-04-C0-00-20-9B-C0-08-18-FB-F0-00-14-FB-F0-03-E9-FB-F0-04-09-FB-F1-00-03-FB-F3-00-47-FB-F3-00-65-C0-10-08-00-03-FB-F1-00-00-00-40",
  "bmp_rpat_info_post_policy_attr": null,
  "bmp_rpat_info_string": [
    "xmlns:rtp=\"urn:huawei:yang:huawei-routing-policy\" select=\"/rtp:routing-policy/rtp:policy-definitions/rtp:policy-definition[rtp:name='RP-C20-IP-IN']/rtp:nodes/rtp:node[rtp:sequence='10']"
  ],
  "writer_id": "ietfint_nfacctd-bmp01_c/1958020"
}
~~~~
