[![Build status](https://github.com/pmacct/pmacct/workflows/ci/badge.svg?branch=master)](https://github.com/pmacct/pmacct/actions)

DOCUMENTATION
=============

- Introduction:
This is an extension of pmacct which enables two collectors establishing BMP session with BGP router, which only one will dump to Kafka.
This is conducted under the project "Highly Availibility of BMP".

In order to avoid the impact of link failure/device failure, there should be redundancy in the data collection. In this project it's done by adding another collector and both esatablishing the same BMP session.
However, having two collectors dumping the messages to Kafka will bring replication, which make the data analyst more difficult. Thus only one collector should dump to KAFKA.
The logic behind choosing the dumping collector is based on the stability and continuity. The dumping collector will not be switched to another when it's working normally in order to ensure continuity. However, it will be switched in un stable conditions, which include:
· Collector breaks
· Link failure
The dumping collector can also be specified by sending SIGRTMIN(34) signal.

- Details:
1.The dumping collector desicion is realized by comparing the timestamp of each collector. The timestamp is set at the establishment of BMP session(or at the lanuching of core process in the code level) and be written to Redis cache. After setting the timestamp, if no link failure or device break happends, the timestamp will not be modified.
In the redis thread, the timestamp will be sent to redis with a timeout of one second. But the timestamp will also be sent per second, in order that the redis keep record of the current timestamp.
Besides, the thread is also getting the timestamps from redis per second, and make comparison between timestamps. If it has a larger timestamp, it's the standby one, vice versa. The active/standby is recorded in the global variable "ingest_flag".

![alt text](https://github.com/Zephyre777/pmacct/blob/master/redis_thread.png)

2.Kafka dumping
Before dumping message to kafka, the program always check whether it has an ingest_flag of value 1. If yes, it dumps, vice versa.

3. SIGRTMIN
SIGRTMIN is set for the core process. Once the core process receives this signal, it will call a self-defined function. In this function it set the regenerate_timestamp_flag which is a global variable. Once the redis thread is aware of this flag it will refresh the timestamp and make it points to now. With that we can set the collector as either active/standby.

4.Temporary Data queue
When we refresh the timestamp either by shutting down collector or sending signal and reset the collector status, the maximun time for status transition could be 2 seconds. It means that there might be data loss during this 2 second, if the collector was initially dumping. Thus we alwasy need to maintain the message for 2 second in case there is a status transition. When there is a status transition, we firstly dump the message i the queue, then although we might have some duplication, we avoid lossing data. 
