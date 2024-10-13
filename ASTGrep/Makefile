include ../common.mk

AL_SERVICE_NAME=ASTGrep
# SERVICE_NAME=assemblyline-service-template

test-dependencies:
	pip install tox
	sudo apt-get install -y libfuzzy-dev

test-quick:
	WORK_DIR=$$(pwd) tox -c ../tox.ini -- -m 'not slow'