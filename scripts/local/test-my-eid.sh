#!/bin/bash

docker run -d --name test-my-eid --restart=always \
  -p 9445:8443 \
  -p 9446:8444 \
  -e SERVER_SERVLET_CONTEXT_PATH=/testeid \
  -e SP_BASE_URI=https://eid.idsec.se \
  -e SPRING_PROFILES_ACTIVE=local \
  docker.eidastest.se:5000/test-my-eid
  