#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
PMACCT_ROOT_LOCATION="$SCRIPT_DIR/../../../"

TAG='_build'

echo "Building pmacct docker images"
docker build --build-arg NUM_WORKERS=$(nproc) -t base:$TAG -f $PMACCT_ROOT_LOCATION/docker/base/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t nfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/nfacctd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmacctd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbgpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbgpd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbmpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbmpd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmtelemetryd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmtelemetryd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t sfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/sfacctd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t uacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/uacctd/Dockerfile_non_root $PMACCT_ROOT_LOCATION || exit $?
