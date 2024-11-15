#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# get docker mem used in MiB
docker stats --no-stream --format "table {{.MemUsage}}" "$1" | awk 'NR==2 {gsub(/MiB/,""); print $1}'