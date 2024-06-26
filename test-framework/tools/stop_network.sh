#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

echo "Stopping pmacct_test_network..."
$SCRIPT_DIR/../library/sh/test_network/delete.sh || exit $?
echo "Test network deleted"
