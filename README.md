[![Build Status](https://travis-ci.org/pmacct/pmacct.svg?branch=master)](https://travis-ci.org/pmacct/pmacct)

DOCUMENTATION
=============

- Online:
  * pmacct wiki: http://wiki.pmacct.net/
  * GitHub: https://github.com/pmacct/pmacct/

- Distribution tarball:
  * ChangeLog: History of features version by version 
  * CONFIG-KEYS: Available configuration directives explained
  * QUICKSTART: Examples, command-lines, quickstart guides
  * FAQS: FAQ document
  * INSTALL: basic installation guide
  * docs/: Miscellaneous internals, UNIX signals, SQL triggers documents 
  * examples/: Sample pmacct and 3rd party tools configurations; sample maps
  * sql/: SQL documentation, default SQL schemas and customization tips

#BUILDING#

- Build GitHub code:
  * git clone https://github.com/pmacct/pmacct.git
  * cd pmacct
  * ./autogen.sh
  * ./configure *[check-out available configure knobs via ./configure --help]* 
  * make
  * make install *[with super-user permission]*
