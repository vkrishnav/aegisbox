.PHONY: build test lint clean

BINARY := bin/aegisbox

build:
	@mkdir -p bin
	go build -o $(BINARY) .
	@echo "Built: $(BINARY)"

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

.DEFAULT_GOAL := build
