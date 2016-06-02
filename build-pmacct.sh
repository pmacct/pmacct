#!/bin/bash
./autogen.sh
./configure --enable-kafka --enable-jansson
make
make install