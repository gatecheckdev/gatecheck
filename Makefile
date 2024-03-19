SRC := $(shell find . -type f -name '*.go')
MAIN_PACKAGE_PATH := ./cmd/gatecheck
BINARY_NAME := ./bin/gatecheck

.PHONY: format test dependencies clean coverage open-coverage build release-snapshot release all

default: all

all: format test build

format:
	$(info ******************** Checking formatting ********************)
	@test -z $(shell gofmt -l $(SRC)) || (gofmt -d $(SRC); exit 1)

test: dependencies
	$(info ******************** Running tests ********************)
	go test -cover ./...

coverage:
	$(info ******************** Generating test coverage ********************)
	go test -coverprofile=coverage.out ./...

open-coverage: coverage
	go tool cover -html=coverage.out

dependencies:
	$(info ******************** Downloading dependencies ********************)
	go mod download

build:
	$(info ******************** Compiling binary to ./bin ********************)
	go build -ldflags="-X 'main.cliVersion=$$(git describe --tags)' -X 'main.gitCommit=$$(git rev-parse HEAD)' -X 'main.buildDate=$$(date -u +%Y-%m-%dT%H:%M:%SZ)' -X 'main.gitDescription=$$(git log -1 --pretty=%B)'" -o ${BINARY_NAME} ${MAIN_PACKAGE_PATH}

release-snapshot:
	goreleaser release --snapshot --rm-dist

release:
	goreleaser release --rm-dist

clean:
	rm -rf ${BINARY_NAME} coverage.out
