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

cd $(dirname ${0})

VARIANT_SPEC=${1}
BUILD_BRANCH=${2}

SENTINEL_PATH=./build_success.txt

rm -f ${SENTINEL_PATH}

bash -ex ./pmacct-deps.sh
bash -ex ./pmacct-self.sh ${VARIANT_SPEC} ${BUILD_BRANCH}

echo "build succeded on "$(date) > ${SENTINEL_PATH}
