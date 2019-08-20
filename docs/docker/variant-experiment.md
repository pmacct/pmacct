not working, but the way to go
why is not working?    
    
    CONTAINER_ID=$(docker run \
        --rm -it -d \
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
        centos7.3-for-pmacct:latest)
    
    docker exec \
        -i ${CONTAINER_ID} \
        "bash docs/docker/build.sh"
    
    docker stop \
        ${CONTAINER_ID}        
    
