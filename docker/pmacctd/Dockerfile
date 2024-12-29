##pmacct (Promiscuous mode IP Accounting package)
##pmacct is Copyright (C) 2003-2020 by Paolo Lucente

#Author: Marc Sune <marcdevel (at) gmail.com>

#This Dockerfile creates an image for pmacctd

FROM base:_build
LABEL maintainer="pmacct Docker Doctors <docker-doctors (at) pmacct.net>"

ENTRYPOINT ["/usr/local/sbin/pmacctd"]
CMD ["-f", "/etc/pmacct/pmacctd.conf"]
