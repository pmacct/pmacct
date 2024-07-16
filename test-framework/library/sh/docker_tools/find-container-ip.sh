#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# check health status of the container, whose name was passed as argument, and consolidates stderr with stdout
#docker inspect --format='{{json .State.Health.Status}}' "$1" 2>&1


docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>&1
