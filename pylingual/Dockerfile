ARG REGISTRY=
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable

FROM python:3.11-slim as builder

WORKDIR /opt
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    apt-get update && apt-get upgrade -y && apt-get install -y git cmake make g++

COPY helpers/build-pylingual.sh helpers/build-pylingual.sh
RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    bash helpers/build-pylingual.sh

FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
# gcc make libssl-dev zlib1g zlib1g-dev libbz2-dev libsqlite3-dev are needed for pyenv - TODO: extract to multi-stage build
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    apt-get update && apt-get install -y curl gcc make libssl-dev zlib1g zlib1g-dev libbz2-dev libsqlite3-dev && apt-get upgrade -y

WORKDIR /opt/al_service

# TODO: multi-stage build?
COPY helpers/install-pyenv.sh helpers/install-pyenv.sh
RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    bash helpers/install-pyenv.sh

COPY --from=builder /opt/pylingual/dist/pylingual*.whl /helpers/
COPY --from=builder /opt/pylingual/pylingual/decompiler_config.yaml /helpers/
COPY --from=builder /opt/python-xdis/dist/xdis*.whl /helpers/

COPY requirements.txt requirements.txt

RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages pip install \
    --no-cache-dir --requirement requirements.txt && \
    pip install --no-cache-dir /helpers/pylingual*.whl && \
    pip install --no-cache-dir /helpers/xdis*.whl && \
    rm -rf ~/.cache/pip

# combine to one step with the upper after ensuring the
COPY helpers/ helpers/
RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages \
    bash helpers/install-pylingual.sh

USER assemblyline
COPY . .

USER root
ARG BASE_TAG=4.6.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

USER assemblyline
# ENV PATH "$HOME/.pyenv/bin:$PATH"