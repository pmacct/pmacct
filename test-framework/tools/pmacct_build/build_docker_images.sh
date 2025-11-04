#!/bin/bash


SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
PMACCT_ROOT_LOCATION="$SCRIPT_DIR/../../../"

TAG='_build'

CUSTOM_LIB_PATH="libnothing.so"

# Using this as a guide for options https://www.redhat.com/en/blog/arguments-options-bash-scripts

echo "Building pmacct docker images"
docker build --build-arg NUM_WORKERS=$(nproc) --build-arg CUSTOM_LIB_PATH=$CUSTOM_LIB_PATH -t base:$TAG -f $PMACCT_ROOT_LOCATION/docker/base/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t nfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/nfacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbgpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbgpd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbmpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbmpd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmtelemetryd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmtelemetryd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t sfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/sfacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t uacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/uacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
