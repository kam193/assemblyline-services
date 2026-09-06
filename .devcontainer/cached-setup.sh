#!/bin/bash

set -e

install -d -m 0755 /etc/apt/keyrings
install -m 0644 /tmp/claude-code.asc /etc/apt/keyrings/claude-code.asc
echo "deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main" \
  | tee /etc/apt/sources.list.d/claude-code.list
apt-get update
apt-get install -y claude-code bash-completion
rm -rf /var/lib/apt/lists/*
python3 -m pip install --upgrade pip
# TODO: one day this should be replaced with a lockfile
python3 -m pip install jupyter ipykernel pytest tox pip-tools
/tmp/inject-bashrc.sh
