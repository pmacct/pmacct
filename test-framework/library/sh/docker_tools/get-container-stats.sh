#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

# get docker statistics in json format
docker stats "$1" --no-stream --format "{{ json . }}"
