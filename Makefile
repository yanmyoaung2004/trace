.PHONY: all build clean test lint vet fmt run

BINARY = innoigniter
GO = go

all: fmt vet build

build:
	$(GO) build -o $(BINARY) ./cmd/$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf .innoigniter/

test:
	$(GO) test ./... -v -count=1

lint:
	$(GO) vet ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

run: build
	./$(BINARY) version

tidy:
	$(GO) mod tidy
	$(GO) mod verify

cross:
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY)-linux-amd64 ./cmd/$(BINARY)
	GOOS=linux GOARCH=arm64 $(GO) build -o $(BINARY)-linux-arm64 ./cmd/$(BINARY)
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY)-darwin-amd64 ./cmd/$(BINARY)
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BINARY)-darwin-arm64 ./cmd/$(BINARY)
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY)-windows-amd64.exe ./cmd/$(BINARY)
