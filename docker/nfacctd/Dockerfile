##pmacct (Promiscuous mode IP Accounting package)
##pmacct is Copyright (C) 2003-2020 by Paolo Lucente

#Author: Marc Sune <marcdevel (at) gmail.com>

#This Dockerfile creates an image for nfacctd

ARG BUILD_REGISTRY=

FROM ${BUILD_REGISTRY:+${BUILD_REGISTRY}/}base:_build
LABEL maintainer="pmacct Docker Doctors <docker-doctors (at) pmacct.net>"

ARG CUSTOM_LIB=libnothing.so
ARG CUSTOM_LIB_PATH=/dev/null/libnothing.so

COPY ${CUSTOM_LIB_PATH}* /usr/local/${CUSTOM_LIB}

ENTRYPOINT ["/usr/local/sbin/nfacctd"]
CMD ["-f", "/etc/pmacct/nfacctd.conf"]
