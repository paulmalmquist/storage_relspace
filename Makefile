.PHONY: build build-fips test test-unit test-fips race lint vuln check run mcp docker

PG_URL ?= postgres://postgres:strongbox@localhost:5432/strongbox_test?sslmode=disable
# Integration tests fail when Postgres is unreachable. `make test-unit` runs without it.
export STRONGBOX_REQUIRE_INTEGRATION ?= 1
BIN ?= bin/strongbox

build:
	go build -o $(BIN) ./cmd/strongbox

build-fips:
	GOFIPS140=v1.0.0 go build -o $(BIN) ./cmd/strongbox

# Integration tests run against PG_URL as a restricted runtime login the harness creates.
test:
	STRONGBOX_TEST_DATABASE_URL="$(PG_URL)" go test ./...

# The whole suite in Go's enforced FIPS mode.
test-fips:
	STRONGBOX_TEST_DATABASE_URL="$(PG_URL)" GOFIPS140=v1.0.0 GODEBUG=fips140=only go test -count=1 ./...

test-unit:
	STRONGBOX_REQUIRE_INTEGRATION= STRONGBOX_TEST_DATABASE_URL= go test ./...

race:
	STRONGBOX_TEST_DATABASE_URL="$(PG_URL)" go test -race -count=1 ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: lint test test-fips vuln

run: build
	$(BIN) init && $(BIN) serve -addr 127.0.0.1:8080

mcp: build
	$(BIN) mcp

docker:
	docker build -t strongbox:dev .

.PHONY: dreamcatcher-bundles dreamcatcher-demo
dreamcatcher-bundles:
	go run ./examples/dreamcatcher/pack -out examples/dreamcatcher/uploads

dreamcatcher-demo:
	docker compose -f examples/dreamcatcher/compose.yaml up --build
