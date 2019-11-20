#/bin/bash

get_lines() {
if [ -f $1  ]; then
	ln_raw=`wc -l < $1`
else
	ln_raw=0
fi
echo $ln_raw
}
