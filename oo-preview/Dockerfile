ARG REGISTRY=
ARG MANIFEST_REGISTRY=ghcr.io/
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN --mount=type=secret,id=apt,target=/etc/apt/apt.conf.d/00cfg \
    echo "deb http://deb.debian.org/debian bookworm contrib non-free" > /etc/apt/sources.list.d/contrib.list \
    && apt update && apt upgrade -y \
    && apt install -y libstdc++6 \
                        libcurl4-gnutls-dev \
                        libc6 \
                        libxml2 \
                        libcurl4 \
                        fonts-dejavu \
                        fonts-opensymbol \
                        fonts-liberation \
                        ttf-mscorefonts-installer \
                        fonts-crosextra-carlito

ARG OO_VERSION=v8.1.0
RUN wget https://github.com/ONLYOFFICE/DocumentBuilder/releases/download/${OO_VERSION}/onlyoffice-documentbuilder_amd64.deb \
    && apt-get install -y ./onlyoffice-documentbuilder_amd64.deb

USER assemblyline
COPY requirements.txt requirements.txt

RUN --mount=type=secret,id=pypi,target=/etc/pip.conf,mode=0444 \
    pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
ARG BASE_TAG=4.5.0.stable
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml && \
    python /opt/al_service/service/finish_installation.py

USER assemblyline
