BIN="./bin"
SRC=$(shell find . -name "*.go")

.PHONY: fmt test install_deps clean coverage ocov

default: all

all: fmt test
	
build:
	$(info ******************** Compile Binary to ./bin ********************)
	mkdir -p bin
	go build -o bin ./...
	
fmt:
	$(info ******************** checking formatting ********************)
	@test -z $(shell gofmt -l $(SRC)) || (gofmt -d $(SRC); exit 1)

test: install_deps
	$(info ******************** running tests ********************)
	go test -cover ./...

coverage:
	$(info ******************** running test coverage ********************)
	go test -coverprofile cover.cov ./...

ocov: coverage
	go tool cover -html=cover.cov


install_deps:
	$(info ******************** downloading dependencies ********************)
	go get -v ./...

# Make sure to have GITHUB_TOKEN env variable defined
release_snapshot:
	goreleaser release --snapshot --clean

release:
	goreleaser release --clean

clean:
	rm -rf $(BIN)
