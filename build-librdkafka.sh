#!/bin/bash

pushd /tmp
git clone https://github.com/edenhill/librdkafka
cd librdkafka
./configure
make
make install
popd