##pmacct (Promiscuous mode IP Accounting package)
##pmacct is Copyright (C) 2003-2023 by Paolo Lucente

#Author: Marc Sune <marcdevel (at) gmail.com>

#This Dockerfile creates a base docker image with pmacct and other useful
#tools for network telemetry and monitoring

FROM debian:bullseye-slim as build-stage
# We don't want man pages
COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes
# This is not the runtime/final image:
#   * we keep some installation steps in different layers to improve cachability
#   * this only covers build deps
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
    libjson-c-dev \
    libnetfilter-log-dev \
    libpcap-dev \
    libpq-dev \
    libsnappy-dev \
    libsqlite3-dev \
    libssl-dev \
    libgnutls28-dev \
    libtool \
    make \
    pkg-config \
    sudo \
    wget \
    zlib1g-dev
WORKDIR /tmp/pmacct/
# About to deal with deps installation
COPY ci/deps.sh ci/
# Parallelism: 2 looks a reasonable default, and bear in mind CI specs
ARG NUM_WORKERS=2
ENV MAKEFLAGS="-j${NUM_WORKERS}"
# Do not check certificates in wget for external deps
ARG DEPS_DONT_CHECK_CERTIFICATE
RUN ./ci/deps.sh
# Actual build
COPY . .
RUN export AVRO_LIBS="-L/usr/local/avro/lib -lavro" && \
  export AVRO_CFLAGS="-I/usr/local/avro/include" && \
  ./autogen.sh && ./configure --enable-mysql --enable-pgsql     \
                              --enable-sqlite3 --enable-kafka   \
                              --enable-geoipv2 --enable-jansson \
                              --enable-rabbitmq --enable-nflog  \
                              --enable-ndpi --enable-zmq        \
                              --enable-avro --enable-serdes     \
                              --enable-redis --enable-gnutls && \
  make install

FROM debian:bullseye-slim as base
LABEL maintainer "pmacct Docker Doctors <docker-doctors (at) pmacct.net>"
# We don't want man pages
COPY ci/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/excludes
COPY --from=build-stage /usr/local/ /usr/local
# Runtime deps
RUN apt-get update && \
  apt-get install -y \
    libmariadb3 \
    libnuma1 \
    libcurl4 \
    libpcap0.8 \
    libpq5 \
    libjson-c3 \
    libnetfilter-log1 \
    libsnappy1v5 \
    libsqlite3-0 \
    libssl1.1 && \
  apt-get -y clean && \
  rm -rf /var/lib/apt/lists/* && \
  ldconfig
ENTRYPOINT ["/bin/bash"]
