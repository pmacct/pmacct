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
  * docs/: Miscellaneous internals, UNIX signals, SQL triggers documents 
  * examples/: Sample configs, maps, AMQP/Kafka consumers, clients 
  * sql/: SQL documentation, default SQL schemas and customization tips

# USING THE DOCKER IMAGE

With docker installed, just pull the base image and you are ready to go:

```bash

 ~# docker pull pmacct/base:latest
 ~# docker run -it pmacct/base

```

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

# RELICENSE INITIATIVE

The pmacct project is looking to make its code base available under a more permissive
BSD-style license. More information about the motivation and process can be found in
this [announcement](https://www.mail-archive.com/pmacct-discussion@pmacct.net/msg03881.html).

# CONTRIBUTING

- Prerequisites:
  * Set up git: https://help.github.com/articles/set-up-git/
  * *[Specify username, a commit email address matching the GitHub profile one, and a SSH key]*

- Code:
  * Fork the pmacct repo: https://help.github.com/articles/fork-a-repo/
  * *[Jot down your code in the local clone of your fork, commit and push code changes to your fork]*
  * Generate a Pull Request: https://help.github.com/articles/about-pull-requests/

- Wiki (documentation and diagrams):
  * Ask by unicast email to be added to the project collaborators
  * *[Edit wiki content online or clone it locally and commit and push changes]* 
  * If having to add a diagram: https://gist.github.com/subfuzion/0d3f19c4f780a7d75ba2
