#!/bin/sh

SCRIPT_DIR=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/.. || exit $?

echo "Installing needed apk packages"
apk add python3 || exit $?
apk add py3-pip || exit $?
apk add python3-dev || exit $?
apk add make || exit $?
apk add gcc || exit $?
apk add bash || exit $?
apk add alpine-sdk || exit $?
apk add librdkafka-dev || exit $?

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
