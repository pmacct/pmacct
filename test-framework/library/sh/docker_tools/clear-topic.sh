#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# find directory, where this script resides
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# dynamically create the json file, which is needed for resetting the topic
echo "{\"partitions\": [{\"topic\": \"$1\", \"partition\": 0, \"offset\": -1}], \"version\":1}" > $SCRIPT_DIR/clear-topic.json
if [[ $? -ne 0 ]] ; then
    exit 1
fi

# copy the json file to the broker container
docker cp $SCRIPT_DIR/clear-topic.json broker:/
if [[ $? -ne 0 ]] ; then
    exit 1
fi

# reset the topic by shifting the low_watermark after the last message
docker exec broker /bin/kafka-delete-records --bootstrap-server broker:9092 --offset-json-file /clear-topic.json
