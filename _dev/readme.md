## Dev AL environment

Dev AL environment based on https://github.com/CybercentreCanada/assemblyline-docker-compose

This setup is modified to the specific development workflow. In particular, AL is started
without the scaler, updater and ingester. Necessary services are intended to start manually.

Use `make gen-key` to generate the self-signed certificate. Then `make pull` to download current
image versions and `make start` to start the appliance. After a while, `make bootstrap` for the first use.

To register new service, use `make register` in the appropriate directory. For standard AL services,
see some helpers in the common.mk - use `make service-xxx` in any directory to run them.

If the service requires an update component, first call `make run-updater` to start the updater container,
and then `make run-with-updates` to start the service connected to the updater.