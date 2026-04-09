.PHONY: help build test clean docker

help:
	@echo "Available targets:"
	@echo "  build      - Build the driver binary"
	@echo "  test       - Run tests"
	@echo "  clean      - Remove built artifacts"
	@echo "  docker     - Build Docker image"

build:
	go build -o hd-driver-auth-github ./cmd/hd-driver-auth-github

test:
	go test -race -v ./...

clean:
	rm -f hd-driver-auth-github

docker:
	docker build -f build/docker/Dockerfile -t hd-driver-auth-github:latest .
