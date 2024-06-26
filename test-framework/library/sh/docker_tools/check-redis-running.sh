#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

docker exec "$1" redis-cli ping
