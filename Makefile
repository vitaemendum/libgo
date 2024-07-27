build:
	@go build -o bin/libgo

run: build
	@./bin/libgo

test:
	@go test -v ./...
