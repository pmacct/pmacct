[![Build status](https://github.com/pmacct/pmacct/workflows/ci/badge.svg?branch=master)](https://github.com/pmacct/pmacct/actions)

DOCUMENTATION
=============
# Functionality

  * Active/standby mode for the BMP collector (or thread) is enabled via the tmp_bmp_daemon_ha config knob (currently undocumented, until the feature is considered GA). The active/standby status is determined by the timestamp of the collector, which is set at startup of the process: a smaller timestamp means that a collector has worked fine for a longer time, and thus can be considered as a stable one, while the other(s), having a larger timestamp due to either just establishing BMP session a later, or crashing while running, will be considered as less stable one(s). (Please note that there can be multiple collectors where more than one collector can be standby but only one will be active)
  The timestamp is written to Redis with key:
  
  ```bash
  [config.name]+[config.cluster_id]+[core_proc_name]+"attachment_time"ß
  e.g. nfacctd-bmp-locB+0+locBbmp-locB01c+attachment_time
  ```
 
  In redis_common.c, the function called p_redis_get_time() performs the following query:
  
  ```bash
  KEYS *(cluster id)+attachment_time
  ```

  The query is replied with information such as: a two dimensional array containing all keys that fit the condition(session_name), and the number of keys that fit the condition(session_num). In order to get timestamps, it does a GET with the key, see code below:
  
  ```bash
 for (int i = 0; i < session_num; i++) 
  {
    redis_host->reply = redisCommand(redis_host->ctx, "GET %s", session_name[i]);
    session_value[i] = strtoll(redis_host->reply->str, &eptr, 0); //eptr is the endpointer, stands for NULL 
    // If there is a timestamp larger than its timestamp, return 0
    if (strtoll(timestamp, &eptr, 0) > session_value[i])
    {
      p_redis_process_reply(redis_host);
      return false;
    }
    // Continue if it's its timestamp
    else if (strtoll(timestamp, &eptr, 0) == session_value[i])
    {
      continue;
    }
  }
```
  
  * Redis is used by each collector for broader cluster management, ie. to exchange timestamp information. Initially, the collector publishes to Redis once per minute. Then such interval decreases in order to exchange information faster. In addition, the collector does also consume timestamp information from Redis with the same rate of publishing. The active/standby status is calculated each time, written to the log and notified by a global variable "dump_flag" which will be used by the Kafka thread afterwards.
  
  * The collector calls the p_kafka_produce_data_to_part() function to dump messages to Kafka. Each time before dumping data, the dump_flag is checked and, if true, publish to the message bus will take place. If false, a data pointer, data length as well as a timestamp is saved in a structure and queued in a global linked list. See code below:
  
  ```bash
struct QNode *newNode(void *k, size_t k_len)
{
  struct QNode *temp = (struct QNode *)malloc(sizeof(struct QNode));
  temp->key = k;
  temp->key_len = k_len;
  struct timeval current_time;
  gettimeofday(&current_time, NULL);                                      // Get time in micro second
  temp->timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec; // Setting the time when redis connects as timestamp for this bmp session
  // temp->next = NULL;
  return temp;
}
  ```

  A thread iteratively goes over the global linked list and removes entries whose timestamp is 2 secs earlier than current time. For dumping data in the linked list, another variable `queue_dump_flag` is used, which is set when there is a change in the value of `dump_flag` (and when it's not the first time getting the `dump_flag`). With the `queue_dump_flag` set, the thread goes through all the data in the list and dumps it before the next new BMP message will be dumped.

# Possible daemon states
(listed according to priority)
Scenario			Daemon A's state    Other daemon's state
Redis Unavailable               active              active
Send signal 34 to A             active              standby
Send signal 35 to A             active              - -
Send signal 36 to A             standby             - -
Only A's timestamp              active              standby
A has smallest timestsmp        active              standby
One tiemstamp smaller than A    standby             - -

# Sending Signals Commands

The main actions that may need to be triggered by commands are the likes of refreshing the timestamp and force to change collector status. To use them, firstly start the collector:

```bash
 ~# sudo systemctl nfacctd-bmp-locA01.service
 ~# sudo systemctl nfacctd-bmp-locB01.service
```

In order to send the signal, one has to seek for the PID of the targeted process. Let's assume that now A is active and B is passive. To search for the process ID, type:

```bash
 ~# sudo ps -ef | grep "nfacctd: Core Process"
```

If one now wants to set B as the active one, one needs to refresh A's timestamp. Simply type:

```bash
 ~# sudo kill -34 collectorA-nfacctd-core-processID
```

Now A is queuing messages while B is dumping. If now one wants to force A to dump as well, type:

```bash
 ~# sudo kill -35 collectorA-nfacctd-core-processID
```

Now both A & B are dumping. If you now want B, which is initially dumping, to stop and queue messages, simply type:

```bash
 ~# sudo kill -36 collectorB-nfacctd-core-processID
```

Now A is dumping and B is queuing messages. However, A has a lower priority and B has a higher priority due to the timestamp. If one wants to set all them back to their normal status, simply type:

```bash
 ~# sudo kill -37 collectorA-nfacctd-core-processID
 ~# sudo kill -37 collectorB-nfacctd-core-processID
```

Then A will be queuing messaging while B will be dumping, just like what is indicated by their timestamps.
