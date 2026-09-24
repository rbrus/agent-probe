.PHONY: all build test vet fmt run clean

all: fmt vet test build

build:
	go build -trimpath -ldflags "-s -w" -o bin/agent-probe ./cmd/agent-probe

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run:
	bash scripts/quickstart.sh

clean:
	rm -rf bin/ build/ dist/ report.*
