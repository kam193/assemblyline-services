FROM mcr.microsoft.com/devcontainers/python:3-3.14-trixie

COPY cached-setup.sh /tmp/setup.sh
COPY bashrc-extras claude-code.asc inject-bashrc.sh /tmp/
RUN chmod +x /tmp/setup.sh && /tmp/setup.sh