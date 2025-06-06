ARG REGISTRY=
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
# FROM debian:bookworm-slim as builder

# RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
#     apt-get update && apt-get upgrade -y && apt-get install -y git cmake make g++

# Removed as it's not used in the current version
# COPY helpers/ helpers/
# RUN bash helpers/build-pycdc.sh

FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    apt-get update && apt-get install -y curl && apt-get upgrade -y

WORKDIR /opt/al_service

COPY requirements.txt requirements.txt
COPY helpers/ helpers/

# TODO: multi-stage build?
RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages pip install \
    --no-cache-dir --requirement requirements.txt && \
    bash helpers/install-deps.sh && \
    rm -rf ~/.cache/pip

# COPY --from=builder /helpers/pycdc /usr/local/bin/pycdc
USER assemblyline
COPY . .

USER root
ARG BASE_TAG=4.6.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

USER assemblyline
