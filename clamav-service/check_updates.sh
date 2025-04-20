#!/bin/sh

# This script checks if there is a new version of clamav available

BASE_TAG=4.6.0.stable
TAG=$(cat VERSION)
REGISTRY=packages.lab.kam193.eu:9443

# make build
CHECK=`docker run --rm -u root --name ClamAVServiceCheck ghcr.io/kam193/assemblyline-service-clamav:${BASE_TAG}${TAG} bash -c "apt-get update && apt-get upgrade --dry-run" | grep clamav-daemon`

echo "${CHECK}"

if [ "${CHECK}" ]; then
    echo "Update available $CHECK"
    # Force recreation of layer by changing the comment
    # VERSION_MARK="Expected clamd: $CHECK"
    # sed -i "s#Expected clamd: .*#$VERSION_MARK#g" Dockerfile
    # make push
else
    echo "No update available"
fi

