ARG REGISTRY=
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN apt-get update && apt-get install -y curl && apt-get upgrade -y

WORKDIR /opt/al_service

COPY requirements.txt requirements.txt
COPY helpers/ helpers/

# TODO: multi-stage build?
RUN PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages pip install \
    --no-cache-dir --requirement requirements.txt && \
    bash helpers/install-pyinstxtractor.sh && \
    rm -rf ~/.cache/pip

USER assemblyline
COPY . .

USER root
ARG BASE_TAG=4.5.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

USER assemblyline
