# Autopilot Security Sensor — Bazel build wrapper
VERSION ?= 0.1.0

.PHONY: all build test test-coverage docker-build docker-push clean lint fmt help

all: build

build:
	bazel build //cmd/agent //cmd/controller //cmd/webhook

test:
	bazel test //...

test-coverage:
	bazel coverage //... --combined_report=lcov

docker-build:
	bazel build //cmd/agent:agent_image //cmd/controller:controller_image //cmd/webhook:webhook_image

docker-push:
	bazel run //cmd/agent:agent_push
	bazel run //cmd/controller:controller_push
	bazel run //cmd/webhook:webhook_push

clean:
	bazel clean

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .

help:
	@echo "APSS - Autopilot Security Sensor"
	@echo ""
	@echo "Targets:"
	@echo "  build         - Build all binaries via Bazel"
	@echo "  test          - Run all tests via Bazel"
	@echo "  test-coverage - Run tests with LCOV coverage report"
	@echo "  docker-build  - Build OCI images via Bazel"
	@echo "  docker-push   - Push OCI images to registry via Bazel"
	@echo "  clean         - Clean Bazel output"