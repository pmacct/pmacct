#!/bin/sh

#    Copyright
#    (c) 2020 Marc Sune <marcdevel@gmail.com>
#    (c) 2020 Claudio Ortega <claudio.alberto.ortega@gmail.com>
#    (c) 2020 Paolo Lucente <paolo@pmacct.net>
#
#    Permission to use, copy, modify, and distribute this software for any
#    purpose with or without fee is hereby granted, provided that the above
#    copyright notice and this permission notice appear in all copies.
#
#    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#Do not delete
set -e

#Ugly hack for libavro; how to avoid?
export AVRO_LIBS="-L/usr/local/avro/lib -L/usr/local/lib64 -lavro"
export AVRO_CFLAGS="-I/usr/local/avro/include -I/usr/local/include"
export LD_LIBRARY_PATH=/usr/local/avro/lib:/usr/local/lib64

#New versions of git complain with "unsafe directory "otherwise due to patches
#for CVE-2022-24765, CVE-2022-24767
git config --global --add safe.directory `pwd`
git config --global --add safe.directory `pwd`/src/external_libs/libcdada

#Build & install
./autogen.sh
./configure --disable-silent-rules $CONFIG_FLAGS || (cat config.log && /bin/false)
make
sudo make install

#Test ?
ls -l src/nfacctd
src/nfacctd -V
