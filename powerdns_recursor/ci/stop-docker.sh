#!/bin/bash

# A script to tear down the powerdns_recursor containers.

set -e

NAME=dd-test-powerdns-recursor

if docker ps -a | grep $NAME >/dev/null; then
  containers=$(docker ps --format '{{.Names}}' --filter name=$NAME)
  stopped_containers=$(docker ps -a --format '{{.Names}}' --filter name=$NAME)

  docker kill $containers 2>/dev/null || true
  docker rm $stopped_containers 2>/dev/null || true
fi
