#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

# Forcefully deleting all traffic containers

#docker ps --all --filter name="traffic-reproducer-" --quiet | while read -r value; do docker rm --force "$value"; done
grep -r "name:" "$SCRIPT_DIR"/../../../tests/*/container-setup.yml | cut -d':' -f3 | \
  while read -r value; do docker rm --force "$value" > /dev/null 2>&1; done
