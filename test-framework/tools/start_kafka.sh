#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Starting Kafka docker compose..."
$SCRIPT_DIR/../library/sh/kafka_compose/start.sh || exit $?
echo "Kafka containers deployed"

out="$( $SCRIPT_DIR/../library/sh/docker_tools/check-container-health.sh schema-registry )"
while [[ "$out" != *"healthy"* ]]; do
  sleep 5
  echo "Waiting for schema-registry to be in healthy state"
  out="$( $SCRIPT_DIR/../library/sh/docker_tools/check-container-health.sh schema-registry )"
done
echo "Kafka infrastructure ready"