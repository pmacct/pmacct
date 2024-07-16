## Test Description (901-redis-connection-loss)

Testing with redis: losing redis connection.

### Provided files:
```
- 901_test.py                    pytest file defining test execution

- nfacctd-00.conf                nfacctd daemon configuration file            HINT: you might want to change redis_ip

- output-log-00.txt              log messages that need to be in the logfile
- output-log-01.txt              log messages that need to be in the logfile
```

### Test execution and results:

1. Part 1: 

- start a redis container
- start nfacctd with kafka normally
- check log messages in "output-log-00.txt" and verify that they are present in the logfile (order of appearence preserved, but there could/will be other logs in between) --> as long as this is successful you can proceed to part 2
- No ERROR or WARN messages are present in the logfile

2. Part 2:

- simulate redis going down (e.g. stop redis container)

Then verify the following

- Log messages in "output-log-01.txt" are present in the logfile (order of appearence preserved, but there could/will be other logs in between)
