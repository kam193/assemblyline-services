include ../common.mk

AL_SERVICE_NAME=Semgrep
# SERVICE_NAME=assemblyline-service-template

PYTHON ?= python3
OPENGREP_DIR ?= $(CURDIR)/.bin
export PATH := $(OPENGREP_DIR):$(PATH)

install-opengrep:
	$(PYTHON) scripts/opengrep.py install --dest $(OPENGREP_DIR) $(ARGS)

update-opengrep:
	$(PYTHON) scripts/opengrep.py update $(ARGS)

test: install-opengrep
