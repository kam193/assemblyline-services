ARG REGISTRY=
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
ARG MANIFEST_REGISTRY=ghcr.io/
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
        && apt-get update \
        && apt-get upgrade -y \
        && apt-get install -y tshark \
        && rm -rf /var/lib/apt/lists/*

USER assemblyline
COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
RUN sed -i "s|\(image: \${REGISTRY}\).*\(kam193/.*\)|\1$MANIFEST_REGISTRY\2|g" service_manifest.yml && \
    sed -i "s/\$SERVICE_TAG/$BASE_TAG$(cat VERSION)/g" service_manifest.yml

USER assemblyline
