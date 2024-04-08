#!/bin/bash

# exit if there is no argument
if [ -z "$2" ]; then
    echo "No arguments supplied"
    exit 1
fi

# send signal to container
docker kill --signal=$2 "$1" # 2>&1
