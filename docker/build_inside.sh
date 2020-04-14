#!/usr/bin/env bash

cd $(dirname ${0})

VARIANT_SPEC=${1}
BUILD_BRANCH=${2}

SENTINEL_PATH=./build_success.txt

rm -f ${SENTINEL_PATH}

bash -ex ./pmacct-deps.sh
bash -ex ./pmacct-self.sh ${VARIANT_SPEC} ${BUILD_BRANCH}

echo "build succeded on "$(date) > ${SENTINEL_PATH}
