#!/bin/sh

# This script checks if there is a new version of clamav available

TAG=$(cat VERSION)
REGISTRY=packages.lab.kam193.eu:9443

docker build -t kam193/assemblyline-service-clamav-check:$TAG --build-arg REGISTRY=$REGISTRY --build-arg TAG=$TAG -f Dockerfile.check_updates .
CHECK=`docker run --rm --name ClamAVServiceCheck kam193/assemblyline-service-clamav-check:$TAG 2>&1 | grep clamav-daemon`

if [ "${CHECK}" ]; then
    echo "Update available $CHECK"
    # Force recreation of layer by changing the comment
    VERSION_MARK="Expected clamd: $CHECK"
    sed -i "s#Expected clamd: .*#$VERSION_MARK#g" Dockerfile
    make push
else
    echo "No update available"
fi

