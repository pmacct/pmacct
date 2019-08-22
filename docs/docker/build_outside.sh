# execute this script with no arguments from the root dir of the git repo workspace,

docker build \
    -f docs/docker/Dockerfile-centos-7.3-for-pmacct \
    -t centos7.3-for-pmacct  .

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

docker exec -i ${CONTAINER_ID} bash docs/docker/build_inside.sh

docker stop ${CONTAINER_ID}