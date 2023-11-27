REGISTRY=${REGISTRY:-}
PUSH_REGISTRY=${PUSH_REGISTRY:-}
SERVICE_NAME=assemblyline-service-template
BASE_TAG=4.4.0.stable

manifest:
	sed -i "s/assemblyline-service-template/${SERVICE_NAME}/g" service_manifest.yml
	sed -i "s/assemblyline-service-template/${SERVICE_NAME}/g" README.md

CACHE=
build: manifest
	docker build -t kam193/${SERVICE_NAME}:latest --build-arg REGISTRY=${REGISTRY} ${CACHE} .

TAG=$(shell cat VERSION)
push: build
	NEW_TAG=$$((${TAG}+1)) && echo $$NEW_TAG > VERSION
	docker tag kam193/${SERVICE_NAME}:latest $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:latest
	docker tag kam193/${SERVICE_NAME}:latest $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)
	docker push $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:${BASE_TAG}$$(cat VERSION)
	docker push $(PUSH_REGISTRY)/kam193/${SERVICE_NAME}:latest

run: build
	docker run --rm --env SERVICE_API_HOST=http://al_service_server:5003 --network=al_registration -e LOG_LEVEL=DEBUG --name ${SERVICE_NAME} kam193/${SERVICE_NAME}:latest

run-with-host: build
	docker run --rm --env SERVICE_API_HOST=http://al_service_server:5003 --network=al_registration --add-host=host.docker.internal:host-gateway -e LOG_LEVEL=DEBUG --name ${SERVICE_NAME} kam193/${SERVICE_NAME}:latest

refresh: CACHE="--no-cache"
refresh: build

test:
	;

