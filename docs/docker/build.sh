# execute this from the root directory in the pmacct git repo workspace

# build libcap

rm -f libpcap-1.9.0.tar.gz

wget https://www.tcpdump.org/release/libpcap-1.9.0.tar.gz
gunzip libpcap-1.9.0.tar.gz
tar xvf libpcap-1.9.0.tar
cd libpcap-1.9.0
./configure --disable-shared
rm libpcap.a
make
cd ..

# build pmacct

rm src/nfacctd

./autogen.sh
./configure \
    --with-pcap-libs=./libpcap-1.9.0 \
    --with-pcap-includes=./libpcap-1.9.0
make clean
make

