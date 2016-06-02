#!/bin/bash
pushd /tmp
 wget https://archive.apache.org/dist/avro/avro-1.8.1/c/avro-c-1.8.1.tar.gz
 tar -xvf avro-c-1.8.1.tar.gz
 pushd avro-c-1.8.1
 mkdir -p build
  pushd build
  cmake .. \
         -DCMAKE_INSTALL_PREFIX=$PREFIX \
         -DCMAKE_BUILD_TYPE=RelWithDebInfo
  make
  make test
  make install
  popd
 popd
popd