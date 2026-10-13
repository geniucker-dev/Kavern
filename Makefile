GO ?= go
PYTHON ?= python3
BIN_DIR ?= build/bin

# Prime the checksum-verified module cache separately with `go mod download`.
export GOTOOLCHAIN := local
export GOPROXY := off
export GOSUMDB := off
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: build test race vet check smoke demo example-tests
build:
	mkdir -p "$(BIN_DIR)"
	$(GO) build -buildvcs=false -o "$(BIN_DIR)/kavernd" ./cmd/kavernd
	$(GO) build -buildvcs=false -o "$(BIN_DIR)/kavern-agent" ./cmd/kavern-agent
	$(GO) build -buildvcs=false -o "$(BIN_DIR)/kavernctl" ./cmd/kavernctl

test:
	$(GO) test ./... -count=1 -timeout=360s

race:
	$(GO) test -race ./... -count=1 -timeout=360s

vet:
	$(GO) vet ./...

check: build test race vet

smoke: build
	$(PYTHON) examples/native-local/demo.py --bin-dir "$(abspath $(BIN_DIR))" --smoke

demo: build
	$(PYTHON) examples/native-local/demo.py --bin-dir "$(abspath $(BIN_DIR))" --interactive

example-tests: build
	KAVERN_EXAMPLE_BIN_DIR="$(abspath $(BIN_DIR))" $(PYTHON) -m unittest discover -s examples/native-local -p '*_test.py' -v
