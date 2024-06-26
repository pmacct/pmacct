#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

$SCRIPT_DIR/stop_traffic_containers.sh
$SCRIPT_DIR/stop_pmacct.sh
$SCRIPT_DIR/stop_kafka.sh
$SCRIPT_DIR/stop_redis.sh
$SCRIPT_DIR/stop_network.sh
