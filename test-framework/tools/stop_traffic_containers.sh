#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Stopping traffic docker containers..."
$SCRIPT_DIR/../library/sh/traffic_docker/stop_all.sh || exit $?
echo "Traffic docker containers undeployed"
