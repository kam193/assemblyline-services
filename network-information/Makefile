include ../common.mk

AL_SERVICE_NAME=Network-Information
# SERVICE_NAME=assemblyline-service-template

run-redis: CONTAINER_NAME=netinfo_cache
run-redis: IMAGE=redis
run-redis: COMMAND=redis-server --maxmemory 20mb --maxmemory-policy allkeys-lru
run-redis: run-dep