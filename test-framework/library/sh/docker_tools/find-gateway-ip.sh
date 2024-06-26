#!/bin/bash

docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' pmacct_test_network 2>&1
