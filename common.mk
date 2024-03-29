REGISTRY?=
PUSH_REGISTRY?=
BASE_IMAGE?=${REGISTRY}/cccs/assemblyline-v4-service-base:4.5.stable
AL_SERVICE_NAME=Template
SERVICE_NAME=assemblyline-service-$(shell echo ${AL_SERVICE_NAME} | tr '[:upper:]' '[:lower:]')
BASE_TAG?=4.5.0.stable

MANIFEST_REGISTRY?=

manifest:
	sed -i "s/al-name-template/${AL_SERVICE_NAME}/g" service_manifest.yml
	sed -i "s/al-name-template/${AL_SERVICE_NAME}/g" README.md
	# sed -i "s/assemblyline-service-template/${SERVICE_NAME}/g" service_manifest.yml
	sed -i "s/assemblyline-service-template/${SERVICE_NAME}/g" README.md
	sed -i 's|\(version: \).*|\1$$SERVICE_TAG|' service_manifest.yml
	sed -i 's|\(image: \).*kam193/.*|\1$${REGISTRY}ghcr.io/kam193/${SERVICE_NAME}:$$SERVICE_TAG|g' service_manifest.yml

CACHE=
build: manifest
	docker build -t kam193/${SERVICE_NAME}:latest \
		--build-arg REGISTRY=${REGISTRY} \
		--build-arg BASE_IMAGE=${BASE_IMAGE} \
		--build-arg MANIFEST_REGISTRY=${MANIFEST_REGISTRY} \
		--build-arg BASE_TAG=${BASE_TAG} \
		${CACHE} .

TAG=$(shell cat VERSION)
bump_version:
	NEW_TAG=$$((${TAG}+1)) && echo $$NEW_TAG > VERSION

tag:
	docker tag kam193/${SERVICE_NAME}:latest $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:latest
	docker tag kam193/${SERVICE_NAME}:latest $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)

push: build tag
	docker push $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)
	docker push $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:latest

release: bump_version push

COMMAND=
ARGS=
CONTAINER_NAME=${SERVICE_NAME}
CONTAINER_NETWORK=al_registration
run: build
	docker run --rm --env SERVICE_API_HOST=http://al_service_server:5003 --network=${CONTAINER_NETWORK} \
	-e LOG_LEVEL=DEBUG \
	-v "${PWD}/../config.yml:/etc/assemblyline/config.yml" \
	-e AL_SERVICE_NAME=${AL_SERVICE_NAME} \
	${ARGS} \
	--name ${CONTAINER_NAME} kam193/${SERVICE_NAME}:latest ${COMMAND}

run-with-host: build
run-with-host: ARGS=--add-host=host.docker.internal:host-gateway
run-with-host: run

run-updater: build
run-updater: COMMAND=python -m service.updater
run-updater: CONTAINER_NAME=${SERVICE_NAME}_update
run-updater: CONTAINER_NETWORK=external
run-updater: ARGS=-e AL_INSTANCE_KEY=changeme
run-updater: run

run-with-updates: ARGS=-e updates_host=${SERVICE_NAME}_update -e updates_port=5003 -e updates_key=changeme
run-with-updates: CONTAINER_NETWORK=external
run-with-updates: run

run-with-external: CONTAINER_NETWORK=external
run-with-external: run

refresh: CACHE="--no-cache"
refresh: build

run-dep: CONTAINER_NETWORK=external
run-dep:
	docker run --rm --network=${CONTAINER_NETWORK} --name ${CONTAINER_NAME} ${ARGS} ${IMAGE} ${COMMAND}

bash:
	docker exec -it ${SERVICE_NAME} bash

test:
	true

print:
	@echo ${SERVICE_NAME}

lint:
	WORK_DIR=$$(pwd) tox -e lint -c ../tox.ini

format:
	WORK_DIR=$$(pwd) tox -e format -c ../tox.ini
