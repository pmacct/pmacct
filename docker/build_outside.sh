#!/usr/bin/env bash

#    Copyright
#    (c) 2019-2020 Claudio Ortega <claudio.alberto.ortega@gmail.com>
#    (c) 2019-2020 Paolo Lucente <paolo@pmacct.net>
#
#    Permission to use, copy, modify, and distribute this software for any
#    purpose with or without fee is hereby granted, provided that the above
#    copyright notice and this permission notice appear in all copies.
#
#    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

BUILD_DOCKER_FILE=${1}
BUILD_DOCKER_TAG=${2}
VARIANT_SPEC=${3}
BUILD_BRANCH=${4}

docker build -f ${BUILD_DOCKER_FILE} -t ${BUILD_DOCKER_TAG} .

PWD=$(pwd)
echo "pwd:"${PWD}

CONTAINER_ID=$(docker run \
    --rm -it -d \
    -v ${PWD}:${PWD} \
    -w ${PWD} \
    ${BUILD_DOCKER_TAG}:latest)

echo "launched container id:" ${CONTAINER_ID}

docker exec -i ${CONTAINER_ID} bash -ex docker/build_inside.sh ${VARIANT_SPEC} ${BUILD_BRANCH}

docker stop ${CONTAINER_ID}

cat -n docker/build_success.txt