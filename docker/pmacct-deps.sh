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
#


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

wget https://github.com/zeromq/libzmq/releases/download/v4.3.2/zeromq-4.3.2.tar.gz
tar xfz zeromq-4.3.2.tar.gz
cd zeromq-4.3.2 && ./configure && make && sudo make install && cd ..
exit_on_error $?

wget https://archive.apache.org/dist/avro/avro-1.9.1/c/avro-c-1.9.1.tar.gz
tar xfz avro-c-1.9.1.tar.gz
cd avro-c-1.9.1 && mkdir build && cd build && cmake .. && make && sudo make install && cd .. && cd ..
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
