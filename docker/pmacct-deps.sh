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

exit_on_error() {
	exit_code=$1
	if [ $exit_code -ne 0 ]; then
		exit $exit_code
	fi
}

BASE_DIR=$(pwd)
DEPS_DIR="dependencies"

rm -rf ${DEPS_DIR} && mkdir ${DEPS_DIR} && cd ${DEPS_DIR}

git clone https://github.com/akheron/jansson
cd jansson && rm -rf ./.git && autoreconf -i && ./configure && make && sudo make install && cd ..
exit_on_error $?

git clone https://github.com/edenhill/librdkafka
cd librdkafka && rm -rf ./.git && ./configure && make && sudo make install && cd ..
exit_on_error $?

git clone https://github.com/alanxz/rabbitmq-c
cd rabbitmq-c && rm -rf ./.git && mkdir build && cd build && cmake -DCMAKE_INSTALL_LIBDIR=lib .. && sudo cmake --build . --target install && cd .. && cd ..
exit_on_error $?

git clone --recursive https://github.com/maxmind/libmaxminddb 
cd libmaxminddb && rm -rf ./.git && ./bootstrap && ./configure && make && sudo make install && cd ..
exit_on_error $?

git clone -b 3.2-stable https://github.com/ntop/nDPI
cd nDPI && rm -rf ./.git && ./autogen.sh && ./configure && make && sudo make install && sudo ldconfig && cd ..
exit_on_error $?

wget --no-check-certificate https://github.com/zeromq/libzmq/releases/download/v4.3.2/zeromq-4.3.2.tar.gz
tar xfz zeromq-4.3.2.tar.gz
cd zeromq-4.3.2 && ./configure && make && sudo make install && cd ..
exit_on_error $?

wget --no-check-certificate https://archive.apache.org/dist/avro/avro-1.9.2/c/avro-c-1.9.2.tar.gz
tar xfz avro-c-1.9.2.tar.gz
cd avro-c-1.9.2 && mkdir build && cd build && cmake .. && make && sudo make install && cd .. && cd ..
exit_on_error $?

git clone https://github.com/confluentinc/libserdes
cd libserdes && rm -rf ./.git && ./configure && make && sudo make install && cd ..
exit_on_error $?

git clone https://github.com/redis/hiredis
cd hiredis && rm -rf ./.git && make && sudo make install && cd ..
exit_on_error $?

cd ..

echo "pwd:"$(pwd)
echo "BASE_DIR:"$BASE_DIR

exit 0
