SERVICES := controlplane policy-engine audit-service sast-worker vuln-intel updater cli

.PHONY: build test lint migrate-up migrate-down docker-up docker-down

build:
	@for svc in $(SERVICES); do \
		echo "Building $$svc..."; \
		go build -o bin/$$svc ./cmd/$$svc; \
	done

test:
	go test ./... -race -count=1

test-integration:
	go test ./test/integration/... -race -count=1 -tags=integration

lint:
	golangci-lint run ./...

migrate-up:
	migrate -path migrations -database "$${DATABASE_URL}" up

migrate-down:
	migrate -path migrations -database "$${DATABASE_URL}" down 1

docker-up:
	docker-compose -f deploy/docker-compose/docker-compose.yml up -d

docker-down:
	docker-compose -f deploy/docker-compose/docker-compose.yml down

clean:
	rm -rf bin/
