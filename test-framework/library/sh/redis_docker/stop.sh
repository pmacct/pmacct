#!/bin/bash

# find directory, where this script resides
SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

# undeploy Redis container
$SCRIPT_DIR/../../../tools/docker_compose_wrapper.sh --env-file $SCRIPT_DIR/../../../settings.conf \
  -f "$SCRIPT_DIR/docker-compose.yml" down
