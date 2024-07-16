## Test Description (303-BGP-high-availability)

The purpose of this test is to verify the BGP High-Availability feature in pmacct ([README](https://github.com/pmacct/pmacct/blob/master/docs/README_BGP_BMP_HA.md)).

### Provided files:
```
- 303_test.py                               pytest file defining test execution

- traffic-00.pcap                           pcap file (for traffic reproducer)
- traffic-reproducer-00.yml                 traffic replay function config file

- nfacctd-00.conf                           nfacctd daemon configuration file for location A
- nfacctd-01.conf                           nfacctd daemon configuration file for location B
- nfacctd-02.conf                           nfacctd daemon configuration file for location C

- output-bgp-00.json                        desired nfacctd kafka output [daisy.bgp topic] containing json messages
```

### Scenarios

- Default scenario: message_timeout=10s, queue_max_size=1000, ha_cluster_id=0
- Scenario-01: message_timeout=5s, queue_max_size=unlimited, ha_cluster_id=30  (just changing some of the HA parameters...)

### Test timeline:

t=0s --> the first full minute after starting the traffic generator

- t=5s: BGP Open message
- t=7s: BGP Keepalive message
- t=8-51s: BGP Update messages (1 update msg per second)

### Test execution and results:

Start the nfacctd deamon one after the other (give 1s delay), like shown in the following table:

|  Action  | Result |  Log Pattern ID(s) |
|:-----:|:-----:|:-------:|
|   Start Daemon Loc A   |  A starts and becomes active | A:1,2 |
|   Wait 1s |   -   | - |
|   Start Daemon Loc B   |  B starts and becomes standby | B:1,3 |
|   Wait 1s |   -   | - |
|   Start Daemon Loc C   |  C starts and becomes standby | C:1,3 |

Also check that the log pattern (if given) is found in the live pmacct log before moving to the next action.

The 3 daemons are configured in HA, meaning that when started they will negotiate who is active and who is stand-by based on the daemon startup time. Since A starts first, he will be active, while B and C will be stand-by. All the daemons are configured to produce BGP data to the daisy.bgp topic.

Then start 3 instances of the traffic reproducer in detached mode: same pcap, same config, only difference is each one is replaying the traffic to one of the nfacctd collectors. The traffic reproducers will not kill the TCP connection after finishing replaying the packets (keep_open=true). 

**HINT**: ensure that the traffic reproducers are not started when time \> XX:55 or time \< XX:10. That's to avoid a situation where traffic repro 1 is started at XX:04 and the others after XX:05 leading to the reproduction being out of sync for the 3 daemons (since the BGP sessions start at XX:05s).

**Now perform the following actions:**

|  Action  | Result | Log Pattern ID(s) |
|:--------------------:|:-----------------:|:-----------------------:|
| Wait 5s |   -   | A:4  B:4 C:4|
| Reset timestamp on A | B will become active (simulate A crashing and reloading) | A:5,3 B:2 |
| Wait 5s |   -   |  - |
| Reset timestamp on B | C will become active (simulate B crashing and reloading) | B:5,3 C:2 |
| Wait 5s |   -   |  - |
| Set C to forced-active | (simulate maintenance mode) | C:6 |
| Set A to forced-standby | (simulate maintenance mode) | A:7 |
| Set B to forced-standby | (simulate maintenance mode) | B:7 |
| Wait 5s |   -   |  - |
| Reset timestamp on C | C has bigger timestamp, but stays active since forced | C:9 |
| Wait 5s |   -   |  - |
| Set A to auto-mode | A becomes active (C is still forced active) | A:8,2 |
| Set B to auto-mode | - | B:8 |
| Wait 5s |   -   |  - |
| Set C to auto-mode | C goes to standby (only A stays active) | C:8,3 |

Also check that the log pattern(s) (if given) is found in the live pmacct log before moving to the next action.

**Important to check:**
- **All** the nfacctd kafka output messages in topic daisy.bgp **need to be in "output-bgp-00.json"**, but some of the messages could be duplicates (and which ones might change between runs depending on when the HA failovers are happening) --> alternative read_and_compare_messages function needs to be developed.

**Also the usual requirements apply:**
- The timestamp values will change between runs.
- The writer_id field can also be ignored as it will change depending on the active deamon producing the messages
- Order of the json messages could change (this means you also have to ignore any sequence numbers when comparing the json output!)
- No ERROR or WARN messages are present in the logfile

### Log pattern table:
|  ID  | Log Pattern |
|:-----:|-----------------------------------------------------|
|   1   | ```${RANDOM} BMP-BGP-HA - Redis connection successful``` |
|   2   | ```${RANDOM} BMP-BGP-HA Daemon state: ACTIVE``` |
|   3   | ```${RANDOM} BMP-BGP-HA Daemon state: STANDBY``` | 
|   4   | ```${RANDOM} [${repro_ip}] BGP peers usage: 1/100``` |
|   5   | ```${RANDOM} BMP-BGP-HA: Local startup timestamp reset triggered.``` |
|   6   | ```${RANDOM} BMP-BGP-HA: Setting daemon to forced-active state.```|
|   7   | ```${RANDOM} BMP-BGP-HA: Setting daemon to forced-standby state.``` |
|   8   | ```${RANDOM} BMP-BGP-HA: Setting daemon back to automatic timestamp-based mode.``` |
|   9   | ```${RANDOM} BMP-BGP-HA Daemon is in forced-mode (ACTIVE): startup timestamp has no influence on state!``` |
|   10  | ```${RANDOM} BMP-BGP-HA Daemon is in forced-mode (STANDBY): startup timestamp has no influence on state!``` |
