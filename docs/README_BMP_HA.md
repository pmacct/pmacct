[![Build status](https://github.com/pmacct/pmacct/workflows/ci/badge.svg?branch=master)](https://github.com/pmacct/pmacct/actions)

DOCUMENTATION
=============
# Functionality

  * Collector will be working on active/standby mode for BMP session(IPFIX won't be affected). This active/standby status is determined by the timestamp of the collector, which is set at the establishment of nfacctd core process. We consider that having a smaller timestamp means that a collector has worked for a longer time, and thus can be considered as a stable one, while the others, having a larger timestamp due to either just establishing bmp session a bit later, or carshing while running, will be considered as less stable ones. (Please note that there can be more than three collectors, more than one collector can be standby but only one will be active.)
  The timestamp is written to redis with key:
  
  ```bash
  [config.name]+[config.cluster_id]+[core_proc_name]+"attachment_time"ß
  e.g. nfacctd-bmp-locB+0+locBbmp-locB01c+attachment_time
  ```
 
  In redis_common.c, I wrote a function called p_redis_get_time(). In this function it queried with command
  
  ```bash
  KEYS *(cluster id)+attachment_time
  ```
  It can get a reply with information such as: a two dimensional array containing all keys that fit the condition(session_name), and the number of keys that fit the condition(session_num). In order to get timestamp, do another GET with the key.
  See code below:
  
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
  
  * Redis is used by each collector to exchange timesamp information. Initially, nfacctd is publishing to redis once per minute. I speed it up to once per second in order to get information faster. 
  In addition, nfacctd is also consuming timestamp information from redis with the same rate as that for publishing. And the active/standby will be calculated each time and be written to the log.
  Then the active/standby status will by notified by a global variable "dump_flag", which will be used by kafka thread afterwards.
  
  * nfacctd is calling the p_kafka_produce_data_to_part() function to dump message to kafka. Each time before dumping, I make the program check with the dump_flag, and pulish only if it's true.
  If it's false, it stores the data pointer, the data lenth as well as when the data is intended to be dumped in as struct and enqueue it in a shared linked list.
  See code below:
  
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
  I created a global linked list and a thread that is iteratively dequeuing nodes in the queue whose timestamp is 2s earlier than current time. I set it as 2s because theoratically the failover does for maximum 2s. In this case it can store data for the past two seconds and dump it ot avoid data loss if the failover happends during dumping.
  
  For dumping data in the list, I created another queue_dump_flag, which will be set when there is a change with the value of dump_flag while it's not the first time getting the dump_flag.
  With the queue_dump_flag, it goes through all the data in the list and dump them before the next new BMP message will be dumped.

# Possible daemon state
(listed according to priority)
situation                       daemon A's state    Other daemon's state
Redis Unavailable               active              active
Send signal 34 to A             active              standby
Send signal 35 to A             active              - -
Send signal 36 to A             standby             - -
Only A's timestamp              active              standby
A has smallest timestsmp        active              standby
One tiemstamp smaller than A    standby             - -

# Sending Signals Commands

The main actions that need to be triggered by commands, are sending the siganls to refresh the timestamp and to force to change collector status. To use them, firstly start the collector:

```bash
 ~# sudo systemctl nfacctd-bmp-locA01.service
 ~# sudo systemctl nfacctd-bmp-locB01.service
```

In order to send the signal, we need to search for the process ID of targeted process. Let's assume that now A is active and B is passive. To search for the process ID, type:

```bash
 ~# sudo ps -ef | grep "nfacctd: Core Process"
```

If you want to now set B as the active one, you need to refresh A's timestamp. Simply type:

```bash
 ~# sudo kill -34 collectorA-nfacctd-core-processID
```

Now A is queuing messages while B is dumping. If you want to now force A to dump as well, type:

```bash
 ~# sudo kill -35 collectorA-nfacctd-core-processID
```

Now both A&B are dumping. If you now want B, which is initially dumping, to stop and queue messages, simply type:

```bash
 ~# sudo kill -36 collectorB-nfacctd-core-processID
```

Now A is dumping and B is queuing messages. However, A has a lower priority and B has a higher priority due to the timestamp. If you want to set all them back to their normal status, simply type:

```bash
 ~# sudo kill -37 collectorA-nfacctd-core-processID
 ~# sudo kill -37 collectorB-nfacctd-core-processID
```

Then A will be queuing messaging while B will be dumping, just like what is indicated by their timestamps.



