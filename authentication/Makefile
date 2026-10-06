# MRNet auth service: two regions plus the global registry, on this machine.
COMPOSE := docker compose -f deploy/compose.yaml

.PHONY: up down reset build compose secrets proto test e2e bench logs ps

up: secrets compose build
	$(COMPOSE) up -d --wait
	@echo "ap1 gateway: https://localhost:8443   eu1 gateway: https://localhost:9443"

build:
	docker build -t mrnet-auth:dev .

compose:
	python3 deploy/gen_compose.py

# Local-only secrets, generated once. HASH_PEPPER and INTERNAL_SECRET are
# shared by all regions; KMS and rotation keys are per region.
secrets: deploy/.env
deploy/.env:
	@{ \
	  for k in HASH_PEPPER INTERNAL_SECRET AP1_KMS_MASTER_KEY AP1_ROTATION_KEY EU1_KMS_MASTER_KEY EU1_ROTATION_KEY; do \
	    echo "$$k=$$(openssl rand -base64 32)"; \
	  done; \
	} > $@
	@echo "wrote $@"

down:
	$(COMPOSE) down

# Removes every container and volume: all users and sessions are deleted.
reset:
	$(COMPOSE) down -v

proto:
	protoc --go_out=. --go_opt=module=mrnet/authentication --go-grpc_out=. --go-grpc_opt=module=mrnet/authentication api/authv1/internal.proto

test:
	go test ./internal/...

e2e:
	go test -tags e2e -count=1 -v ./e2e/

bench:
	go test -run '^$$' -bench . -benchmem ./internal/tokens ./internal/hashing

logs:
	$(COMPOSE) logs -f --tail=50

ps:
	$(COMPOSE) ps
