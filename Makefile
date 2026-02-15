.PHONY: build test lint clean install fmt vet

# Build the CLI binary
build:
	go build -o bin/pact ./cmd/pact

# Install the CLI binary
install:
	go install ./cmd/pact

# Run all tests
test:
	go test ./... -v

# Run tests with race detector
test-race:
	go test ./... -race -v

# Run tests with coverage
test-cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Format code
fmt:
	gofmt -s -w .

# Vet code
vet:
	go vet ./...

# Lint (requires golangci-lint: https://golangci-lint.run/usage/install/)
lint:
	golangci-lint run

# Format + vet + lint + test
check: fmt vet lint test

# Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html
