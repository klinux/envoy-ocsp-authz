IMAGE ?= envoy-ocsp-authz:dev

.PHONY: test build image vet tidy
test:
	go test ./...
vet:
	go vet ./...
build:
	CGO_ENABLED=0 go build -trimpath -o bin/authz ./cmd/authz
image:
	docker build -t $(IMAGE) .
tidy:
	go mod tidy
