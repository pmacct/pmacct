#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Starting test network pmacct_test_network..."
$SCRIPT_DIR/../library/sh/test_network/create.sh || exit $?
echo "Network deployed"
