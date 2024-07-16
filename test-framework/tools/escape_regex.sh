#!/bin/bash

if [ -z "$1" ]; then
    echo "No argument supplied"
    exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

python $SCRIPT_DIR/../library/py/escape_regex.py $1
