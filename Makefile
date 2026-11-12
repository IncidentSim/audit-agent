.PHONY: build test vet check
build:
	go run tools/build.go
test:
	go test ./...
vet:
	go vet ./...
check: test vet build
