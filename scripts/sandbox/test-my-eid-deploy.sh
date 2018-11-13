#!/bin/bash

echo Pulling Docker image ...
docker pull docker.eidastest.se:5000/test-my-eid

echo Undeploying ...
docker rm test-my-eid --force

echo Re-deploying ...

docker run -d --name test-my-eid --restart=always \
  -p 9011:8443 \
  -p 9019:8009 \
  -e SP_BASE_URI=https://eid.idsec.se \
  -e SERVER_SERVLET_CONTEXT_PATH=/testmyeid \
  -e SPRING_PROFILES_ACTIVE=sandbox \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/test-my-eid/logs:/var/log/test-my-eid \
  -v /opt/docker/test-my-eid/etc:/etc/test-my-eid \
  -v /opt/docker/test-my-eid/tmp:/tmp/test-my-eid \
  docker.eidastest.se:5000/test-my-eid
  