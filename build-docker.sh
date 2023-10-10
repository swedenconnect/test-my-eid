#!/bin/bash

mvn clean install

docker build -t docker.eidastest.se:5000/test-my-eid:latest --platform linux/amd64 .
