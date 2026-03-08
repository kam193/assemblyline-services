
gen-key:
	openssl req -nodes -x509 -newkey rsa:4096 -keyout ./config/nginx.key -out ./config/nginx.crt -days 3650 -subj "/C=CA/ST=Ontario/L=Ottawa/O=CCCS/CN=assemblyline.localhost"

pull:
	docker compose pull --ignore-buildable
	COMPOSE_BAKE=true docker compose build
	docker compose -f bootstrap-compose.yaml pull

bootstrap:
	docker compose -f bootstrap-compose.yaml up

start:
	docker compose up

start-detached:
	docker compose up -d

restart-dispatcher:
	docker compose restart dispatcher_minimal