# Introduction

Our pmacct build is tested using docker over 16 plugins variants, inside 
either a Centos 8 container or Ubuntu Bionic, either case while running 
inside an Ubuntu (Travis') VM.

These are the benefits of building pmacct using Docker:
- you may build pmacct for yourself in a server in which the host linux distro, version, and dependencies are all different from the target.
- you may build pmacct in Jenkins/Bitbucker pipelie or Travis, for which you cannot/dont want to control the linux distro, version, and dependencies, but it has Docker engine available


# Procedure

Download the latest stable version of Docker Community Edition from the link below, and follow their instructions: 
    
    https://docs.docker.com/install/


# Build for all plugin variants

execute this single command from the root of the git workspace

    bash -ex docker/build_from_travis.sh ubuntu
       
or
       
    bash -ex docker/build_from_travis.sh centos
            
            
# to obtain the executables for a subset of the plugin variants

use the same command above, but first modify the file 

    docker/build_self.sh 

and make the variable CONFIG_FLAGS contain only those variant(s) you are interested in.
