#!/usr/bin/env python3
import argparse
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def ipv4_packet(payload):
    src = socket.inet_aton("192.0.2.10")
    dst = socket.inet_aton("192.0.2.20")

    tcp = struct.pack(
        "!HHIIHHHH",
        49152,
        1790,
        1,
        0,
        (5 << 12) | 0x18,
        65535,
        0,
        0,
    )

    total_len = 20 + len(tcp) + len(payload)
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src,
        dst,
    )
    ip = ip_without_checksum[:10] + struct.pack("!H", checksum(ip_without_checksum)) + ip_without_checksum[12:]

    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x0800)
    return eth + ip + tcp + payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("payload")
    parser.add_argument("pcap")
    args = parser.parse_args()

    with open(args.payload, "rb") as payload_file:
        frame = ipv4_packet(payload_file.read())

    now = int(time.time())
    pcap_global = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pcap_record = struct.pack("<IIII", now, 0, len(frame), len(frame)) + frame

    with open(args.pcap, "wb") as pcap_file:
        pcap_file.write(pcap_global)
        pcap_file.write(pcap_record)


if __name__ == "__main__":
    main()
