#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# create topic, whose name was passed as argument
docker exec broker /bin/kafka-topics --bootstrap-server broker:9092 --create --topic $1
