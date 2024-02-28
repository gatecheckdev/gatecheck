INSTALL_DIR := env('INSTALL_DIR', '/usr/local/bin')

# build gatecheck binary
build:
    mkdir -p bin
    go build -ldflags="-X 'main.cliVersion=v0.5.0-pre' -X 'main.gitCommit=$(git rev-parse HEAD)' -X 'main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)' -X 'main.gitDescription=$(git log -1 --pretty=%B)'" -o ./bin ./cmd/gatecheck

# build and install binary
install: build
    cp ./bin/gatecheck {{ INSTALL_DIR }}/gatecheck

# unit testing with coverage
test:
    go test -cover ./...

# golangci-lint view only
lint:
    golangci-lint run --fast

# golangci-lint fix linting errors and format if possible
fix:
    golangci-lint run --fast --fix

# Locally serve documentation
# serve-docs:
# 	mdbook serve
