ARG REGISTRY=
ARG BASE_IMAGE=cccs/assemblyline-v4-service-base:stable
FROM ${BASE_IMAGE}

ENV SERVICE_PATH service.al_run.AssemblylineService

USER root
RUN apt-get update && apt-get upgrade -y && apt-get install -y wget libc6 libfontconfig1 libfreetype6 libglib2.0-0 libice6 libsm6 libssl1.1 libxrender1

RUN wget https://cdn.download.comodo.com/cis/download/installs/linux/cav-linux_x64.deb && \
    dpkg -i --ignore-depends=libssl0.9.8 cav-linux_x64.deb && \
    chmod 755 /opt/COMODO/*.sh && \
    chmod 644 /opt/COMODO/*.so && \
    chmod 644 /opt/COMODO/*.so.* && \
    chgrp assemblyline /opt/COMODO/scanners/bases.cav && \
    chmod 664 /opt/COMODO/scanners/bases.cav

# changing group & mode on scanner to allow DB updates

USER assemblyline
COPY requirements.txt requirements.txt

RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

USER root
RUN sed -i "s/\$VERSION/$(cat VERSION)/g" service_manifest.yml

USER assemblyline

# wget -O /opt/COMODO/scanners/bases.cav http://download.comodo.com/av/updates58/sigs/bases/bases.cav

# dpkg -i --ignore-depends=libssl0.9.8 cav-linux_x64.deb
# sudo chmod 755 /opt/COMODO/*.sh
# sudo chmod 644 /opt/COMODO/*.so
# sudo chmod 644 /opt/COMODO/*.so.*
# sudo chmod 644 /usr/local/Trolltech/Qt-4.7.4-Comodo/lib/*.so
# sudo chmod 644 /usr/local/Trolltech/Qt-4.7.4-Comodo/lib/*.so.*
# sudo chmod 644 /usr/local/Trolltech/Qt-4.7.4-Comodo/plugins/sqldrivers/*.so

# /opt/COMODO/post_setup.sh -> instead: sh /opt/COMODO/load_cmdagent.sh restart

# /opt/COMODO/cmdscan -v -s /var/lib/assemblyline/eicar
# -----== Scan Start ==-----
# /var/lib/assemblyline/eicar ---> Found Virus, Malware Name is Malware
# -----== Scan End ==-----
# Number of Scanned Files: 1
# Number of Found Viruses: 1
