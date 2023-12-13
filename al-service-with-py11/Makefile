include ../common.mk

SERVICE_NAME=assemblyline-service-base-py11

AL_VERSION=4.4.0
BASE_NAME=assemblyline-base-py11

BASE_TAG=$(shell cat BASE_VERSION)
CACHE=

manifest:
	true

build-base:
	docker build -t kam193/${BASE_NAME}:latest --build-arg version=${AL_VERSION} --build-arg REGISTRY=${REGISTRY}/ -f Dockerfile.base ${CACHE} ./assemblyline-base
	docker tag kam193/${BASE_NAME}:latest ${REGISTRY}/kam193/${BASE_NAME}:latest

bump_version-base:
	NEW_TAG=$$((${BASE_TAG}+1)) && echo $$NEW_TAG > BASE_VERSION

push-base: build-base
	docker tag kam193/${BASE_NAME}:latest ${PUSH_REGISTRY}/kam193/${BASE_NAME}:latest
	docker tag kam193/${BASE_NAME}:latest ${PUSH_REGISTRY}/kam193/${BASE_NAME}:${BASE_TAG}$$(cat BASE_VERSION)
	docker push ${PUSH_REGISTRY}/kam193/${BASE_NAME}:latest
	docker push ${PUSH_REGISTRY}/kam193/${BASE_NAME}:${BASE_TAG}$$(cat BASE_VERSION)

build-service:
	docker build -t kam193/${SERVICE_NAME}:latest --build-arg REGISTRY=${REGISTRY}/ --build-arg version=${AL_VERSION} --build-arg base=kam193/${BASE_NAME} -f Dockerfile.service ${CACHE} ./assemblyline-v4-service
	docker tag kam193/${SERVICE_NAME}:latest ${REGISTRY}/kam193/${SERVICE_NAME}:latest

bump_version-service:
	NEW_TAG=$$((${TAG}+1)) && echo $$NEW_TAG > VERSION

push-service: build-service
	docker tag kam193/${SERVICE_NAME}:latest ${PUSH_REGISTRY}/kam193/${SERVICE_NAME}:latest
	docker tag kam193/${SERVICE_NAME}:latest ${PUSH_REGISTRY}/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)
	docker push ${PUSH_REGISTRY}/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)
	docker push ${PUSH_REGISTRY}/kam193/${SERVICE_NAME}:latest

refresh-service: CACHE="--no-cache"
refresh-service: build-service