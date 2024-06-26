#!/bin/sh

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/.. || exit $?

echo "Installing needed apk packages"
apt-get -y install python3 || exit $?
apt-get -y install python3-pip || exit $?
apt-get -y install python3-dev || exit $?
apt-get -y install make || exit $?
apt-get -y install gcc || exit $?
apt-get -y install bash || exit $?
#apt-get install alpine-sdk || exit $?
apt-get -y install librdkafka-dev || exit $?
apt-get -y install docker || exit $?

echo "Installing python library requirements"
pip install -r requirements.txt || exit $?

echo "Pulling docker images from repository"
cat settings.conf | grep -v "#" | grep "_IMG=" | awk -F '=' '{print $2}' | while read -r value; do
  if [ ! -z $value ]; then
    docker pull "$value"
  fi
done

echo "Building traffic reproducer docker images"
cd tools/pcap_player
./build_docker_image.sh
