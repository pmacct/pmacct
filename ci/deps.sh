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
fi
echo "WGET_FLAGS: ${WGET_FLAGS}"
echo "MAKEFLAGS: ${MAKEFLAGS}"

# Don't pollute /
mkdir -p /tmp
cd /tmp

# Dependencies (not fulfilled by Dockerfile)
git clone https://github.com/akheron/jansson
cd jansson ; rm -rf ./.git ; autoreconf -i ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

git clone https://github.com/edenhill/librdkafka
cd librdkafka ; rm -rf ./.git ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

wget ${WGET_FLAGS} https://github.com/alanxz/rabbitmq-c/archive/refs/tags/v0.11.0.tar.gz
mv v0.11.0.tar.gz rabbitmq-c-0.11.0.tar.gz
tar xfz rabbitmq-c-0.11.0.tar.gz
cd rabbitmq-c-0.11.0 ; rm -rf ./.git ; mkdir build ; cd build ; cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib .. ; sudo cmake --build . --target install ; cd .. ; cd ..

git clone --recursive https://github.com/maxmind/libmaxminddb
cd libmaxminddb ; rm -rf ./.git ; ./bootstrap ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

git clone -b 4.6-stable https://github.com/ntop/nDPI
cd nDPI ; rm -rf ./.git ; ./autogen.sh ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; sudo ldconfig ; cd ..

git clone -b v4.3.4 https://github.com/zeromq/libzmq
cd libzmq ; ./autogen.sh ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

wget ${WGET_FLAGS} https://archive.apache.org/dist/avro/avro-1.11.1/c/avro-c-1.11.1.tar.gz
tar xfz avro-c-1.11.1.tar.gz
cd avro-c-1.11.1 ; mkdir build ; cd build ; cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. ; make ; sudo make install ; cd .. ; cd ..

git clone -b v7.2.2 https://github.com/confluentinc/libserdes
cd libserdes ; rm -rf ./.git ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

git clone https://github.com/redis/hiredis
cd hiredis ; rm -rf ./.git ; make ; sudo make install ; cd ..

git clone https://github.com/network-analytics/udp-notif-c-collector
cd udp-notif-c-collector ; git checkout v0.6.1 ; rm -rf ./.git ; ./bootstrap ; ./configure --prefix=/usr/local/ ; make ; sudo make install ; cd ..

# Make sure dynamic linker is up-to-date
ldconfig
