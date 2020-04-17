#!/usr/bin/env bash

#
#   pmacct (Promiscuous mode IP Accounting package)
#   pmacct is Copyright (C) 2003-2020 by Paolo Lucente
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
#   02111-1307, USA.
#
#   pmacct Docker-related files are Copyright (C) 2019-2020 by:
#
#   Claudio Ortega <claudio.alberto.ortega@gmail.com>
#   Paolo Lucente <paolo@pmacct.net>

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