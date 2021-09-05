#!/bin/sh

#    Copyright
#    (c) 2020 Marc Sune <marcdevel@gmail.com>
#    (c) 2020 Claudio Ortega <claudio.alberto.ortega@gmail.com>
#    (c) 2020 Paolo Lucente <paolo@pmacct.net>
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

# Do not delete
set -e

#wget options
WGET_N_RETRIES=30
WGET_WAIT_RETRIES_S=10
WGET_FLAGS="-t $WGET_N_RETRIES --waitretry=$WGET_WAIT_RETRIES_S"
if [ "${DEPS_DONT_CHECK_CERTIFICATE}" ]; then
    WGET_FLAGS="${WGET_FLAGS} --no-check-certificate"
    GIT_SSL_NO_VERIFY=true
fi
echo "WGET_FLAGS: ${WGET_FLAGS}"
echo "MAKEFLAGS: ${MAKEFLAGS}"

# Don't pollute /
mkdir -p /tmp
cd /tmp

gh_retrieve(){
    ORG=$1
    REPO=$2
    TAG=$3

    echo "Downloading $ORG $REPO $TAG"
    git clone --branch $TAG --recursive https://www.github.com/$ORG/$REPO
}

gh_build(){
    ORG=$1
    REPO=$2
    TAG=$3

    BUILD_CMD=$4

    gh_retrieve $ORG $REPO $TAG && \
    cd $REPO && \

    sh -c "$BUILD_CMD" && \
    cd .. && \
    
    rm -rf $REPO    
}


# Dependencies (not fulfilled by Dockerfile)
gh_build "akheron" "jansson" "v2.13.1" "autoreconf -i && ./configure && make && sudo make install" && \

gh_build "edenhill" "librdkafka" "v1.7.0" "./configure && make && sudo make install" && \

gh_build "alanxz" "rabbitmq-c" "v0.11.0" "mkdir build && cd build && cmake -DCMAKE_INSTALL_LIBDIR=lib .. && sudo cmake --build . --target install && cd .." && \

gh_build "maxmind" "libmaxminddb" "1.6.0" "./bootstrap && ./configure && make && sudo make install" && \

gh_build "ntop" "nDPI" "3.4-stable" "./autogen.sh && ./configure && make && sudo make install && sudo ldconfig" && \

gh_build "zeromq" "libzmq" "v4.3.2" "./autogen.sh && ./configure && make && sudo make install" && \

gh_build "apache" "avro" "release-1.9.2" "cd lang/c && mkdir build && cd build && cmake .. && make && sudo make install && cd ../.." && \

gh_build "confluentinc" "libserdes" "v7.0.0" "rm -rf ./.git && ./configure ; make && sudo make install" && \

gh_build "redis" "hiredis" "v1.0.0" "rm -rf ./.git && make && sudo make install" && \

gh_build "insa-unyte" "udp-notif-c-collector" "v0.5.1" "./bootstrap && ./configure && make && sudo make install" && \

# Make sure dynamic linker is up-to-date
ldconfig
