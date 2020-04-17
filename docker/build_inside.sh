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

cd $(dirname ${0})

VARIANT_SPEC=${1}
BUILD_BRANCH=${2}

SENTINEL_PATH=./build_success.txt

rm -f ${SENTINEL_PATH}

bash -ex ./pmacct-deps.sh
bash -ex ./pmacct-self.sh ${VARIANT_SPEC} ${BUILD_BRANCH}

echo "build succeded on "$(date) > ${SENTINEL_PATH}
