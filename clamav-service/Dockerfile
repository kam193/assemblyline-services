ARG REGISTRY=
ARG BASE_IMAGE=${REGISTRY:-}/cccs/assemblyline-v4-service-base:stable
ARG MANIFEST_REGISTRY=ghcr.io/
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.main.ClamAVService

USER root
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    apt-get update && \
    apt-get install -y clamav-daemon gcc && \
    mkdir /opt/clamav_db/ && \
    chown assemblyline:clamav /opt/clamav_db/

USER assemblyline
COPY requirements.txt requirements.txt

RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_TAG=4.6.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

# # UPGRADE CLAMAV-DAEMON
# RUN apt-get update && apt-get install -y clamav-daemon # Expected clamd: docker.io/jammy-updates 24.0.5-0ubuntu1~22.04.1 amd64 [aktualizowany z: 20.10.25-0ubuntu1~22.04.2]

USER assemblyline
