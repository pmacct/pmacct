#!/bin/bash

# exit if there is no argument
if [ -z "$1" ]; then
  echo "No argument supplied"
  exit 1
fi
if [ $# -ne 1 ]; then
  echo "Only one argument can be given"
  exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

cd $SCRIPT_DIR/..

test_file="$( ls -d tests/${1}*/*test*.py 2>/dev/null )"
if [ -z $test_file ]; then
  echo "Test case not found"
  exit 1
fi
echo "Test file: $test_file"
params_line=$( grep -m 2 "KModuleParams" $test_file | tail -n 1 )

test_dir=$( dirname $test_file)
test_filename=${test_dir}/tmp.py

cat > $test_filename << EOL
from library.py.test_params import KModuleParams
import sys
$params_line
def test(debug_core):
    pass
EOL

python3 -m pytest $test_filename --log-cli-level=DEBUG
