#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Stopping pmacct docker containers..."
$SCRIPT_DIR/../library/sh/pmacct_docker/stop_force.sh || exit $?
echo "Pmacct docker containers undeployed"
