[![Build Status](https://travis-ci.org/pmacct/pmacct.svg?branch=master)](https://travis-ci.org/pmacct/pmacct)

DOCUMENTATION
=============

- Online:
  * GitHub Wiki Pages: https://github.com/pmacct/pmacct/wiki
  * GitHub master code: https://github.com/pmacct/pmacct/

- Distribution tarball:
  * ChangeLog: History of features version by version 
  * CONFIG-KEYS: Available configuration directives explained
  * QUICKSTART: Examples, command-lines, quickstart guides
  * FAQS: FAQ document
  * INSTALL: basic installation guide
  * docs/: Miscellaneous internals, UNIX signals, SQL triggers documents 
  * examples/: Sample configs, maps, AMQP/Kafka consumers, clients 
  * sql/: SQL documentation, default SQL schemas and customization tips

# BUILDING

- Resolve dependencies, ie.:
  * apt-get install libpcap-dev pkg-config libtool autoconf automake bash *[Debian/Ubuntu]*
  * yum install libpcap-devel pkgconfig libtool autoconf automake bash *[CentOS/RHEL]*

- Build GitHub code:
  * git clone https://github.com/pmacct/pmacct.git
  * cd pmacct
  * ./autogen.sh
  * ./configure *[check-out available configure knobs via ./configure --help]* 
  * make
  * make install *[with super-user permission]*
