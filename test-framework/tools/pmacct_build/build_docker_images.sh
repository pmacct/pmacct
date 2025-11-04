#!/bin/bash


SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
PMACCT_ROOT_LOCATION="$SCRIPT_DIR/../../../"

TAG='_build'

CUSTOM_LIB_PATH="ci/libnothing.so*"

# Using this as a guide for options https://www.redhat.com/en/blog/arguments-options-bash-scripts

# Get the options
while getopts ":hp:" option; do
   case $option in
      h) # help
         echo "This script builds all images required to run pmacct tests"
         echo "options:"
         echo "-h                        Print this help."
         echo "-p  {path to library}     Build the images with the custom parsing library found locally at the specified path (the path must be relative to the root of the pmacct directory)."
         exit;;
      p) # custom Parsing lib
         echo "Custom parsing lib detected : $OPTARG"
         CUSTOM_LIB_PATH=$OPTARG;;
     \?) # invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done


echo "Building pmacct docker images"
docker build --build-arg NUM_WORKERS=$(nproc) --build-arg CUSTOM_LIB_PATH=$CUSTOM_LIB_PATH -t base:$TAG -f $PMACCT_ROOT_LOCATION/docker/base/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t nfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/nfacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbgpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbgpd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmbmpd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmbmpd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t pmtelemetryd:$TAG -f $PMACCT_ROOT_LOCATION/docker/pmtelemetryd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t sfacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/sfacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
docker build --build-arg NUM_WORKERS=$(nproc) -t uacctd:$TAG -f $PMACCT_ROOT_LOCATION/docker/uacctd/Dockerfile $PMACCT_ROOT_LOCATION || exit $?
