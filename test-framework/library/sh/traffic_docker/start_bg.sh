#!/bin/bash

PCAP_MOUNT_DIR="$1"
ID="$2"
IP_ADDRESS="$3"
MULTI_OR_EMPTY="$4" # either "multi", or null/empty
if [ -z "$3" ]; then
  echo "Bad arguments supplied"
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
source $SCRIPT_DIR/../../../settings.conf

IP_OPT="--ip"
if [[ "$IP_ADDRESS" == *"::"* ]]; then
  IP_OPT="--ip6"
fi

IMAGE_NAME=$TRAFFIC_REPRO_IMG
if [ "$MULTI_OR_EMPTY" = "multi" ]; then
  IMAGE_NAME=$TRAFFIC_REPRO_MULTI_IMG
fi

echo "Starting traffic container with mounted folder: $1, ID: $2 and IP: $3"
docker run -d -v ${PCAP_MOUNT_DIR}:/pcap \
          --network pmacct_test_network \
          $IP_OPT $IP_ADDRESS \
          --name traffic-reproducer-"$ID" \
          $IMAGE_NAME
