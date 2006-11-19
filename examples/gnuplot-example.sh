#!/bin/bash

# This file aims to be a trivial example on how to interface pmacctd/nfacctd memory
# plugin to GNUPlot (http://www.gnuplot.info) to make graphs from data gathered from
# the network.
#
# The following does the following assumptions (but these could be easily changed):
#
# - You are using a PostgreSQL database with two tables: 'acct_in' for incoming traffic
#   and 'acct_out' for outcoming traffic
# - You are aggregating traffic for 'src_host' in 'acct_out' and for 'dst_host' in
#   'acct_in'
# - You have enabled 'sql_history' to generate timestamps in 'stamp_inserted' field;
#   because the variable $step is 3600, the assumption is: 'sql_history: 1h'
#
# After having populated the files 'in.txt' and 'out.txt' run gnuplot the following way:
#
# > gnuplot gnuplot.script.example > plot.png
#

PGPASSWORD="arealsmartpwd"
export PGPASSWORD

j=0
step=3600
output_in="in.txt"
output_out="out.txt"

rm -rf $output_in
rm -rf $output_out

RESULT_OUT=`psql -U pmacct -t -c "SELECT SUM(bytes) FROM acct_out WHERE ip_src = '192.168.0.133' GROUP BY stamp_inserted;"`
RESULT_IN=`psql -U pmacct -t -c "SELECT SUM(bytes) FROM acct_in WHERE ip_dst = '192.168.0.133' GROUP BY stamp_inserted;"`

j=0
for i in $RESULT_IN
do
  echo $j $i >> $output_in
  let j+=$step
done

j=0
for i in $RESULT_OUT
do
  echo $j $i >> $output_out
  let j+=$step
done
