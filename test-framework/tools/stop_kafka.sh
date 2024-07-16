#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Stopping Kafka docker compose..."
$SCRIPT_DIR/../library/sh/kafka_compose/stop.sh || exit $?
echo "Kafka docker compose undeployed"
