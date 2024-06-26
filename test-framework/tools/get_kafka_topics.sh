#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/..

cat > reader.py.tmp << EOL
from confluent_kafka import Consumer
import json
consumer_config  = {
       'bootstrap.servers': 'localhost:9092',
       'security.protocol': 'PLAINTEXT',
       'group.id': 'smoke_test',
       'auto.offset.reset': 'earliest'}
consumer = Consumer(consumer_config)
for topic in consumer.list_topics().topics:
    print(topic)
EOL

python reader.py.tmp
rm reader.py.tmp
