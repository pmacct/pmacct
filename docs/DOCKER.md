# Official pmacct docker containers documentation

Docker images are one of the easiest ways to start using pmacct. They are also a
powerful and simple technology to deploy pmacct in production, for example combining
it with [docker-compose](https://docs.docker.com/compose/) or deploying them on
a [Kubernetes cluster (k8s)](https://kubernetes.io/).

## Where to download them

The official pmacct docker image registry is in [docker hub](https://hub.docker.com/r/pmacct).

Available daemon containers:

  * [nfacctd](https://hub.docker.com/r/pmacct/nfacctd)
  * [pmacctd](https://hub.docker.com/r/pmacct/pmacctd)
  * [pmbgpd](https://hub.docker.com/r/pmacct/pmbgpd)
  * [pmbmpd](https://hub.docker.com/r/pmacct/pmbmpd)
  * [pmtelemetryd](https://hub.docker.com/r/pmacct/pmtelemetryd)
  * [sfacctd](https://hub.docker.com/r/pmacct/sfacctd)
  * [uacctd](https://hub.docker.com/r/pmacct/uacctd)

All daemons come with **all plugins and supports compiled-in**.

### Tags

Containers are published with the following tags:

  * `latest`: latest stable image of that container
  * `vX.Y.Z`: version specific tag. This container will always exist, once released.
  * `bleeding-edge`: only for the brave. Latest commit on `master`. This container
                     is not recommended to be used in production.

## How to use them (docker/docker-compose only)

```
 ~# docker pull pmacct/pmacctd:latest
 ~# docker run -v /path/to/pmacctd.conf:/etc/pmacct/pmacctd.conf pmacct/pmacctd
```

To use another daemon, e.g. `nfacctd`, just replace `pmacct/pmacctd` with `pmacct/nfacctd` in both commands.

### Configuration files

All daemons expect a pmacct configuration file in `/etc/pmacct/<name_of_daemon>.conf`.

Note: When using `-v` ([bind mounts](https://docs.docker.com/storage/bind-mounts/)), make sure the HOST path is an **absolute path**.

### Operations

Once running, regular `docker` tools can be used for basic things. A non-extensive
list:

* `docker ps`: list the docker containers in the system
* `docker logs`: inspect logs
* `docker stats`: monitor container resource usage
* `docker pause`/`docker unpause`: pause/unpause the execution of a container

### Sniffing on network interfaces (`libpcap`)

By default, docker containers run in an isolated network enviornment. If daemons
need to access to host network interfaces to sniff traffic (e.g. `pmacctd`),
[privileged mode ](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) and [host network](https://docs.docker.com/network/host/) is required.

```
marc@pmacct:~/tmp$ docker run --privileged --network host -v /home/marc/tmp/pmacctd.conf:/etc/pmacct/pmacctd.conf pmacct/pmacctd:latest
```

## Troubleshooting a pmacct docker container

When reporting a bug, you might be asked to add additional debugging information.
This section covers the basics on some of these procedures.

Troubleshooting typically involves starting containers manually, and in interactive
mode, to install additional debugging tools. To do so, launch the container with the options:

```
marc@pmacct:~/tmp$ docker run -it -v /home/marc/tmp/pmacctd.conf:/etc/pmacct/pmacctd.conf --entrypoint /bin/bash pmacct/pmacctd:latest
root@dca4471bf893:/#
```

### Core dumps

Containers can be started (`docker`/`docker-compose`) with the option to generate
a coredump on abort (`--ulimit core=-1`).

Docker containers run in the kernel of the HOST, and therefore inherit the coredump
configuration (`core_pattern`). To modify it, refer to your OS/Distribution manual.

One thing to mention is that the location of the coredumps is important. It
simplifies things that coredumps are outputted in a dedicated folder
(e.g. `/tmp/cores/`). Container's filesystem is, by definition, volatile,
so coredump(s) will be lost after the daemon aborts and container is
destroyed/restarted. To avoid that it should be mounted as a volume:

```
marc@pmacct:~/tmp$ mkdir -p cores
marc@pmacct:~/tmp$ docker run --ulimit core=-1 -v /home/marc/tmp/cores:/tmp/cores -v /home/marc/tmp/pmacctd.conf:/etc/pmacct/pmacctd.conf pmacct/pmacctd:latest
```

### Using a debugger (`gdb`/`cgdb`)

In the shell of the container, start the program with `gdb` and follow the
regular debugging process:

```
root@dca4471bf893:/# gdb pmacctd
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
   <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from pmacctd...done.
(gdb) run
```

### Using `valgrind`

`valgrind` is a great tool to help the debugging memory errors, among other things.
Please note that `valgrind` slows down significantly the execution.

In the shell of the container do:

_Step 1_: install `valgrind`:

```
root@dca4471bf893:/# apt-get update && apt-get -y install valgrind
Get:1 http://security.debian.org/debian-security buster/updates InRelease [65.4 kB]
Get:2 http://deb.debian.org/debian buster InRelease [121 kB]
Get:3 http://deb.debian.org/debian buster-updates InRelease [51.9 kB]

...
```

_Step 2_: launch the daemon with `valgrind` and options, and let the error condition happen or run for a while:

```
root@dca4471bf893:/# valgrind --leak-check=full --track-origins=yes --trace-children=yes pmacctd
==536== Memcheck, a memory error detector
==536== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==536== Using Valgrind-3.14.0 and LibVEX; rerun with -h for copyright info
==536== Command: pmacctd
==536==
WARN: [cmdline] No plugin has been activated; defaulting to in-memory table.

...
```

_Step 3_: if the program is still running after the condition stop it with `Ctrl+C`. You should see a final report, like:

```
...

==538==
==538== HEAP SUMMARY:
==538==     in use at exit: 24,154 bytes in 58 blocks
==538==   total heap usage: 1,345 allocs, 1,287 frees, 297,541 bytes allocated
==538==
==538== 456 (96 direct, 360 indirect) bytes in 1 blocks are definitely lost in loss record 27 of 29
==538==    at 0x483577F: malloc (vg_replace_malloc.c:299)
==538==    by 0x1607B1: initsetproctitle (setproctitle.c:101)
==538==    by 0x118705: main (pmacctd.c:577)
==538==
==538== LEAK SUMMARY:
==538==    definitely lost: 96 bytes in 1 blocks
==538==    indirectly lost: 360 bytes in 11 blocks
==538==      possibly lost: 0 bytes in 0 blocks
==538==    still reachable: 23,698 bytes in 46 blocks
==538==         suppressed: 0 bytes in 0 blocks
==538== Reachable blocks (those to which a pointer was found) are not shown.
==538== To see them, rerun with: --leak-check=full --show-leak-kinds=all
==538==
==538== For counts of detected and suppressed errors, rerun with: -v
==538== ERROR SUMMARY: 3 errors from 3 contexts (suppressed: 0 from 0)
```

Make sure to send the entire log until and including the final report.

### Opening a shell on a running container

You can open a shell on an existing running container.

_Step 1_: identify the container:

```
marc@pmacct:~/tmp$ docker ps
CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS       PORTS                  NAMES
dca4471bf893   pmacct/pmacctd:latest   "pmacctd"                2 hours ago    Up 2 hours                          adoring_keldysh
```

_Step 2_: open a shell:

```
marc@pmacct:~/tmp$ docker exec -it dca4471bf893 /bin/bash
root@dca4471bf893:/#
```

## FAQ

##### `ERROR: [/etc/pmacct/<daemon_name>.conf] path is not a regular file.`

This happens when the container can't find `/etc/pmacct/<daemon_name>.conf`, and
typically happens when either:

* HOST file path is not an absolute path:

```
marc@pmacct:~/tmp$ docker run -v pmacctd.conf:/etc/pmacct/pmacctd.conf pmacct/pmacctd:latest
ERROR: [/etc/pmacct/pmacctd.conf] path is not a regular file.
```

* There is typo in the TARGET file path. E.g: missing a `d` in the configuration file name in the TARGET:

```
marc@pmacct:~/tmp$ docker run -v /home/marc/tmp/pmacctd.conf:/etc/pmacct/pmacct.conf pmacct/pmacctd:latest
ERROR: [/etc/pmacct/pmacctd.conf] file not found.
marc@Mriya:~/tmp$
```

Solution:

```
docker run -v /home/marc/tmp/pmacctd.conf:/etc/pmacct/pmacctd.conf pmacct/pmacctd:latest
```

## Advanced

### Creating a custom layer on top

A special container, [base](https://hub.docker.com/r/pmacct/base) container,
that is the base of the rest of containers, with all pmacct daemons installed and
`bash` as an entry point is also published, with the same tag structure as the rest
of the containers.

This image can be used to to create your customized docker image, with different
entrypoints or other tools in.

### Building your Docker image from scratch

If you still feel you need to compile your own custom version of pmacct, you
can take a look at the `Dockerfile` in the folder `docker/base` as a starting point.
