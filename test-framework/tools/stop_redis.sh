#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Stopping Redis docker container..."
$SCRIPT_DIR/../library/sh/redis_docker/stop.sh || exit $?
echo "Redis docker container undeployed"
