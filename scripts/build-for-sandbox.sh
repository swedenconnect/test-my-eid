#!/bin/bash
#
# Build script for depoying a Docker image to docker repo that is used for Sweden Connect Sandbox
#
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SANDBOX_DOCKER_REPO=docker.eidastest.se:5000
IMAGE_NAME=${SANDBOX_DOCKER_REPO}/test-my-eid2

if [ -z "$SANDBOX_DOCKER_USER" ]; then
  echo "The SANDBOX_DOCKER_USER variable must be set"
  exit 1
fi

if [ -z "$SANDBOX_DOCKER_PW" ]; then
  echo "The SANDBOX_DOCKER_PW variable must be set"
  exit 1
fi

source ${SCRIPT_DIR}/build.sh -i ${IMAGE_NAME} -p linux/amd64

echo "Logging in to ${SANDBOX_DOCKER_REPO} ..."
echo $SANDBOX_DOCKER_PW | docker login $SANDBOX_DOCKER_REPO -u $SANDBOX_DOCKER_USER --password-stdin

echo "Pushing image to ${SANDBOX_DOCKER_REPO} ..."
docker push ${IMAGE_NAME}:latest
 

