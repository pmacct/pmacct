#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )

PMACCT_LOCATION="$SCRIPT_DIR/../../../"

TAG='_build'

echo "Building pmacct docker images"
docker build -t pmacct-base:$TAG -f $SCRIPT_DIR/base/Dockerfile $PMACCT_LOCATION || exit $?

docker build -t nfacctd:$TAG -f $SCRIPT_DIR/nfacctd/Dockerfile_non_root $PMACCT_LOCATION || exit $?
docker build -t pmbmpd:$TAG -f $SCRIPT_DIR/pmbmpd/Dockerfile_non_root $PMACCT_LOCATION || exit $?
docker build -t pmbgpd:$TAG -f $SCRIPT_DIR/pmbgpd/Dockerfile_non_root $PMACCT_LOCATION || exit $?

