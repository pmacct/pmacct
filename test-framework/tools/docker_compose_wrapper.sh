#!/bin/bash

DOCKER_COMPOSE_COMMAND="docker compose"

docker compose version > /dev/null 2>&1
if [[ "$?" != "0" ]]; then
  DOCKER_COMPOSE_COMMAND="docker-compose"
fi

eval "$DOCKER_COMPOSE_COMMAND $*"
