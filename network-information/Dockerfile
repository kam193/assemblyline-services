ARG REGISTRY=
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    apt-get update && apt-get upgrade -y && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

USER assemblyline
COPY requirements.txt requirements.txt

RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
ARG BASE_TAG=4.6.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

USER assemblyline
