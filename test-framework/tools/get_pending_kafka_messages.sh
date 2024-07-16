#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
  echo "Kafka topic name needs to be passed as argument"
  exit 1
fi
if [ -z "$2" ]; then
  echo "Avro or PlainJson needs to be passed as argument"
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/..

python << EOL
from library.py.kafka_consumer import KMessageReaderAvro, KMessageReaderPlainJson
import json, time
reader = KMessageReader${2}('${1}')
reader.connect()
time.sleep(5)
messages = reader.get_all_pending_messages()
print('Read ' + str(len(messages)) + ' messages')
for msg in messages:
  print(json.dumps(msg))
EOL

