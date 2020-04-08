#!/usr/bin/env bash

cd $(dirname ${0})

SENTINEL_PATH=./build_success.txt
BUILD_BRANCH=$1

rm -f ${SENTINEL_PATH}
bash -ex ./pmacct-deps.sh
bash -ex ./pmacct-self.sh ${BUILD_BRANCH}
echo "build succeded on "$(date) > ${SENTINEL_PATH}
