#!/bin/bash
./autogen.sh
./configure --enable-kafka --enable-jansson
make
make install
LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH