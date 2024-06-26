#!/bin/bash

function print_help() {
  echo "Usage:   ./play_traffic.sh <absolute path to pcap folder in test results> [-d]"
  echo "          -d is used for deploying a detached container"
}

# exit if there is no argument
if [ -z "$1" ]; then
  print_help
  exit 1
fi
if [ -n "$2" ] && [ "$2" != "-d" ]; then
  print_help
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Starting pcap player"
$SCRIPT_DIR/../library/sh/traffic_docker/start_docker_compose.sh ${1}/docker-compose.yml $2 || exit $?
if [ "$2" == "-d" ]; then
  echo "Traffic being replayed in the background"
else
  echo "Traffic replayed"
fi
