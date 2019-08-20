# Introduction

These are the benefits of building pmacct using Docker:
- you can build pmacct in a server in which the host linux distro, version, and dependencies are all different from the equivalent in the targetted deployment server.
- you can build pmacct inside a Jenkins server for which you cannot/dont want to control the linux distro, version, and dependencies
- you can build pmacct in the cloud, inside a platform like or similar to bitbucket pipelines

The paradox now is that, to get isolated from the list of dependencies, you will need a new dependency: Docker 
The advantage is still that such dependency is the only one you will need to build pmacct binaries from and for any linux target platform.
The extra bonus is that you may use this strategy to build almost any other software, not only pmacct.


# Procedure

## Get latest docker engine community edition

Download the latest stable version of Docker Community Edition from here:
    
    https://docs.docker.com/install/

and follow instructions. 


## Put pmacct dependencies inside a Dockerfile

The key for the advantage of this procedure is that all pmacct dependencies will reside  
inside a Dockerfile, under source control. 
We provide a working example of such a Dockerfile for Centos 7.3 in this same directory.
You can adapt this Dockerfile to any target linux OS distro,version you would need,
by keeping one Dockerfile per target.


## Clone/checkout your pmacct workspace for the version you want to build

    cd ~
    git clone https://github.com/pmacct/pmacct.git
    cd pmacct 
    git checkout 1.7.3


## Start the docker container

    docker build \
        -f docs/docker/Dockerfile-centos-7.3-for-pmacct \
        -t centos7.3-for-pmacct  .
        
    docker run \
        --rm -it \
        --network host \
        --user $(id -u) \
        -v $HOME:$HOME \
        -v /etc/group:/etc/group \
        -v /etc/passwd:/etc/passwd \
        -v /etc/shadow:/etc/shadow \
        -v /etc/sudoers:/etc/sudoers \
        -v /etc/hosts:/etc/hosts \
        -v /etc/resolv.conf:/etc/resolv.conf \
        -w $(pwd) \
        centos7.3-for-pmacct:latest


## Build from inside the docker container
    
    docs/docker/build.sh
    exit


## Verify the image is good

Outside the container execute pmacct with the version command line option

    src/nfacctd -V
