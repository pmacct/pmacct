#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# check running status of the container, whose name was passed as argument, and consolidates stderr with stdout
docker inspect --format="{{ .State.Running }}" "$1" 2>&1
