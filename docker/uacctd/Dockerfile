##pmacct (Promiscuous mode IP Accounting package)
##pmacct is Copyright (C) 2003-2020 by Paolo Lucente

#Author: Marc Sune <marcdevel (at) gmail.com>

#This Dockerfile creates an image for uacctd

FROM base:_build
MAINTAINER Marc Sune <marcdevel (at) gmail.com>

ENTRYPOINT ["/usr/local/sbin/uacctd"]
CMD ["-f", "/etc/pmacct/uacctd.conf"]
