#!/bin/bash

# find directory, where this script resides
SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

# deploy Redis by passing the settings file, where docker image URLs are defined
$SCRIPT_DIR/../../../tools/docker_compose_wrapper.sh --env-file $SCRIPT_DIR/../../../settings.conf \
  -f "$SCRIPT_DIR/docker-compose.yml" up -d
# docker compose (two words) does not work on Debian (Jenkins slave)