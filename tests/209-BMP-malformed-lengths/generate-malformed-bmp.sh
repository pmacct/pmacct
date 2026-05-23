#!/usr/bin/env bash
set -eu

usage() {
  echo "usage: $0 <tcp-short-length|packet-short-length> <output-file>" >&2
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

case_name=$1
output=$2

case "$case_name" in
  tcp-short-length)
    # First-stage TCP framing reads version + 32-bit BMP length.
    # Advertised total length is 4, which is smaller than the 6-byte common header.
    printf '\003\000\000\000\004' > "$output"
    ;;
  packet-short-length)
    # Full BMP common header: version=3, len=4, type=init.
    # This reaches bmp_process_packet() through pcap_savefile mode.
    printf '\003\000\000\000\004\004' > "$output"
    ;;
  *)
    usage
    exit 2
    ;;
esac
