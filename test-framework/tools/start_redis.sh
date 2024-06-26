#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Starting Redis docker container..."
$SCRIPT_DIR/../library/sh/redis_docker/start.sh || exit $?
echo "Redis started"
