SERVICE_NAME := identity_service

.PHONY: install test build run lint tidy coverage

install:
	go mod download

test:
	go test ./... -race -count=1 -parallel 4

coverage:
	go test ./... -count=1 -parallel 4 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -n 1

build:
	docker build -t $(SERVICE_NAME):local .

run:
	go run ./cmd/server

lint:
	golangci-lint run ./...

tidy:
	go mod tidy
