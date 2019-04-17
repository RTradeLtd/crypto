all: deps install

.PHONY: deps
deps:
	GO111MODULE=on go mod vendor

.PHONY: install
install:
	go install ./cmd/temporal-crypto
