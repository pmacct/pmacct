FROM ubuntu:trusty
MAINTAINER Elodina, support@elodina.net

RUN apt-get update
RUN apt-get install -y libtool autoconf cmake git build-essential g++ automake libpcap-dev libpq-dev python pkg-config libjansson-dev

WORKDIR /build
