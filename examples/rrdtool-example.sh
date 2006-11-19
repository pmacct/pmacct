#!/bin/sh

# This file aims to be a trivial example on how to interface pmacctd/nfacctd memory
# plugin to RRDtool (people.ee.ethz.ch/~oetiker/webtools/rrdtool/) to make graphs 
# from data gathered from the network.
#
# This script has to be invoked timely from crontab:
# */5 * * * * /usr/local/bin/rrdtool-example.sh 
#
# The following command feeds a two DS (Data Sources) RRD with incoming and outcoming
# traffic (in bytes) between two hosts; the '-r' switch makes counters 'absolute': they
# are zeroed after each query.

/usr/local/bin/rrdtool update /tmp/test.rrd N:`/usr/local/bin/pmacct -c src_host,dst_host -N 192.168.0.133,192.168.0.100 -r`:`/usr/local/bin/pmacct -c src_host,dst_host -N 192.168.0.100,192.168.0.133 -r`

