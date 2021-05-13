##pmacct (Promiscuous mode IP Accounting package)
##pmacct is Copyright (C) 2003-2020 by Paolo Lucente

#Author: Marc Sune <marcdevel (at) gmail.com>

#This Dockerfile creates a base docker image with pmacct and other useful
#tools for network telemetry and monitoring

FROM debian:buster-slim as build-stage
LABEL maintainer "pmacct Docker Doctors <docker-doctors (at) pmacct.net>"

# We don't want man pages
COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes

#Copy installer script
COPY . /tmp/pmacct/

#Create a single compressed layer, as some dependencies (deps.sh)
#can be later removed, so try to make it as lightweight as possible
RUN apt-get update && \
  apt-get install -y \
    autoconf \
    automake \
    bash \
    bison \
    cmake \
    default-libmysqlclient-dev \
    libnuma-dev \
    flex \
    gcc \
    g++ \
    git \
    libcurl4-openssl-dev \
    libjansson-dev \
    libnetfilter-log-dev \
    libpcap-dev \
    libpq-dev \
    libsnappy-dev \
    libsqlite3-dev \
    libssl-dev \
    libgnutls28-dev \
    libstdc++-8-dev \
    libtool \
    make \
    pkg-config \
    sudo \
    wget \
    zlib1g-dev && \
  cd /tmp/pmacct && \
  ./ci/deps.sh && \
  export AVRO_LIBS="-L/usr/local/avro/lib -lavro" && \
  export AVRO_CFLAGS="-I/usr/local/avro/include" && \
  ( make maintainer-clean || /bin/true ) && \
  ./autogen.sh && ./configure --enable-mysql --enable-pgsql     \
                               --enable-sqlite3 --enable-kafka   \
                               --enable-geoipv2 --enable-jansson \
                               --enable-rabbitmq --enable-nflog  \
                               --enable-ndpi --enable-zmq        \
                               --enable-avro --enable-serdes     \
                               --enable-redis --enable-gnutls && \
  sudo make -j$(nproc) install && \
  cd .. && \
  apt-get purge -y \
    autoconf \
    automake \
    bison \
    cmake \
    gcc \
    g++ \
    flex \
    git \
    libtool \
    make \
    pkg-config && \
  apt-get autoremove -y && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/* /tmp/*

ENTRYPOINT ["/bin/bash"]
