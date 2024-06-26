#!/bin/bash

IMG=debian

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Double-checking that submodules are correclty pulled"
cd $SCRIPT_DIR/traffic-reproducer
git submodule update --init --recursive

echo "Building traffic reproducer docker image"
docker build -t traffic-reproducer:_build -f "$SCRIPT_DIR"/multi/Dockerfile_$IMG "$SCRIPT_DIR" || exit $?
