#!/bin/sh

# This file aims to be a trivial example on how to interface pmacctd/nfacctd memory
# plugin to MRTG (people.ee.ethz.ch/~oetiker/webtools/mrtg/) to make graphs from
# data gathered from the network.
#
# This script has to be invoked timely from crontab:
# */5 * * * * /usr/local/bin/mrtg-example.sh 
#
# The following command collects incoming and outcoming traffic (in bytes) between
# two hosts; the '-r' switch makes counters 'absolute': they are zeroed after each
# query.

unset IN
unset OUT

IN=`/usr/local/bin/pmacct -c src_host,dst_host -N 192.168.0.100,192.168.0.133 -r`
OUT=`/usr/local/bin/pmacct -c src_host,dst_host -N 192.168.0.133,192.168.0.100 -r`

echo $IN
echo $OUT
echo 0
echo 0
