include ../common.mk

AL_SERVICE_NAME=Hashlookup
# SERVICE_NAME=assemblyline-service-template

run-redis: CONTAINER_NAME=hashlookup_redis
run-redis: IMAGE=redis
run-redis: COMMAND=redis-server --maxmemory 20mb --maxmemory-policy allkeys-lru
run-redis: run-dep