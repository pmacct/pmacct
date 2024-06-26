#!/bin/bash

# find directory, where this script resides
SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

# exit if bad arguments
if [ -z "$1" ]; then
    echo "No docker-compose file supplied"
    exit 1
fi
DOCKER_COMPOSE_FILE="$1"
$SCRIPT_DIR/../../../tools/docker_compose_wrapper.sh -f $DOCKER_COMPOSE_FILE down
