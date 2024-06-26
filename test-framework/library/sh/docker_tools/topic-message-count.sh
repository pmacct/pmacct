#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# prints a message line containing the number of messages currently in the topic, whose name was passed
# as first argument
docker exec broker /bin/kafka-run-class kafka.tools.GetOffsetShell --bootstrap-server broker:9092 --topic "$1"
