ARG REGISTRY=
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN apt-get update && apt-get upgrade -y

USER assemblyline
COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
RUN sed -i "s/\$VERSION/$(cat VERSION)/g" service_manifest.yml

USER assemblyline
