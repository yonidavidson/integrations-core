#!/bin/bash

# A script to create the Apache containers.

set -e

NAME='dd-test-powerdns-recursor'
PORT=8082
PORT2=5353

if docker ps -a | grep $NAME >/dev/null; then
  echo 'the containers already exist, we have to remove them'
  bash powerdns_recursor/ci/stop-docker.sh
fi

docker create --expose $PORT2/udp --expose $PORT/udp -p $PORT:$PORT/udp -p $PORT2:$PORT2/udp --name $NAME datadog/powerdns_recursor
docker cp ./powerdns_recursor/ci/recursor.conf $NAME:/etc/powerdns/recursor.conf
docker start $NAME

# It doesn't come up immediately, we have to wait to ensure it's up.
sleep 10
