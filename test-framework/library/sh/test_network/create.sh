#!/bin/bash

# Create network for use throughout the test framework
# 172.21.1.10, 172.21.1.11 and 172.21.1.12: kafka containers
# 172.21.1.13: pmacct
# 172.21.1.101, 102, 103, ...: traffic reproducers

docker network create --subnet=172.21.1.0/24 --subnet=fd25::/64 --ipv6 pmacct_test_network
