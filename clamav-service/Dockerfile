ARG REGISTRY=
ARG BASE_IMAGE=${REGISTRY:-}/cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.main.ClamAVService

USER root
RUN apt-get update && \
    apt-get install -y clamav-daemon gcc && \
    mkdir /opt/clamav_db/ && \
    chown assemblyline:assemblyline /opt/clamav_db/

USER assemblyline
COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
RUN sed -i "s/\$VERSION/$(cat VERSION)/g" service_manifest.yml

# UPGRADE CLAMAV-DAEMON
RUN apt-get update && apt-get install -y clamav-daemon # Expected clamd: docker.io/jammy-updates 24.0.5-0ubuntu1~22.04.1 amd64 [aktualizowany z: 20.10.25-0ubuntu1~22.04.2]

USER assemblyline
