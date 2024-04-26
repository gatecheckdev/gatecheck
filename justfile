INSTALL_DIR := env('INSTALL_DIR', '/usr/local/bin')

# build gatecheck binary
build:
    mkdir -p bin
    go build -ldflags="-X 'main.cliVersion=$(git describe --tags)' -X 'main.gitCommit=$(git rev-parse HEAD)' -X 'main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)' -X 'main.gitDescription=$(git log -1 --pretty=%B)'" -o ./bin ./cmd/gatecheck

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

release-snapshot:
    goreleaser release --snapshot --rm-dist

release:
    goreleaser release --rm-dist

upgrade:
    git status --porcelain | grep -q . && echo "Repository is dirty, commit changes before upgrading." && exit 1 || exit 0
    go get -u ./...
    go mod tidy

# Locally serve documentation
serve-docs:
    mdbook serve
