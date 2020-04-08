#!/usr/bin/env bash

declare -a CONFIG_FLAGS
CONFIG_FLAGS[0]="--enable-debug --enable-mysql --enable-pgsql --enable-sqlite3 --enable-kafka --enable-geoipv2 --enable-jansson --enable-rabbitmq --enable-nflog --enable-ndpi --enable-zmq --enable-avro --enable-serdes --enable-redis"
CONFIG_FLAGS[1]="--enable-mysql --enable-pgsql --enable-sqlite3 --enable-kafka --enable-geoipv2 --enable-jansson --enable-rabbitmq --enable-nflog --enable-ndpi --enable-zmq --enable-avro --enable-serdes --enable-redis"
CONFIG_FLAGS[2]="--enable-debug --enable-jansson --enable-zmq --enable-kafka"
CONFIG_FLAGS[3]="--enable-jansson --enable-zmq --enable-kafka"
CONFIG_FLAGS[4]="--enable-debug --enable-jansson --enable-zmq"
CONFIG_FLAGS[5]="--enable-jansson --enable-zmq"
CONFIG_FLAGS[6]="--enable-debug --enable-jansson --enable-kafka --enable-avro --enable-serdes"
CONFIG_FLAGS[7]="--enable-jansson --enable-kafka --enable-avro --enable-serdes"
CONFIG_FLAGS[8]="--enable-debug --enable-jansson --enable-kafka"
CONFIG_FLAGS[9]="--enable-jansson --enable-kafka"
CONFIG_FLAGS[10]="--enable-debug --enable-zmq"
CONFIG_FLAGS[11]="--enable-zmq"
CONFIG_FLAGS[12]="--enable-debug --enable-jansson"
CONFIG_FLAGS[13]="--enable-jansson"
CONFIG_FLAGS[14]="--enable-debug"
CONFIG_FLAGS[15]=""

export AVRO_LIBS="-L/usr/local/avro/lib -lavro"
export AVRO_CFLAGS="-I/usr/local/avro/include"
export LD_LIBRARY_PATH=/usr/local/lib

if [[ ( ${1} == "" ) ]]; then
  BUILD_BRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')
else
  BUILD_BRANCH=${1}
fi

for config_loop_var in "${CONFIG_FLAGS[@]}"; do

    echo BEGIN-1 --- build pmacct based on CONFIG_FLAGS := ${config_loop_var}

    rm -rf pmacct
    git clone --single-branch --branch ${BUILD_BRANCH} https://github.com/pmacct/pmacct.git

    cd pmacct
    rm -rf ./.git
    ./autogen.sh
    ./configure
    make
    sudo make install

    cd ..

    echo END-1   --- build pmacct based on CONFIG_FLAGS := ${config_loop_var}
    echo "pwd(1):"$(pwd)

    ls -l pmacct/src/nfacctd
    pmacct/src/nfacctd -V

done
