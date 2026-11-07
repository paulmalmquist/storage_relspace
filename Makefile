.PHONY: install lint typecheck test test-pg security check openapi run mcp docker docker-fips

PG_URL ?= postgresql+psycopg://postgres:strongbox@localhost:5432/strongbox_test

install:
	pip install -e ".[dev,gcp,s3,mcp]"

lint:
	ruff format --check src tests
	ruff check src tests

typecheck:
	mypy

test:
	pytest -q

test-pg:
	STRONGBOX_TEST_DATABASE_URL="$(PG_URL)" pytest -q

security:
	bandit -q -r src
	pip-audit

check: lint typecheck test

openapi:
	strongbox openapi > docs/openapi.json

run:
	strongbox init && strongbox serve --host 127.0.0.1 --port 8080

mcp:
	strongbox mcp --transport stdio

docker:
	docker build -t strongbox:dev .

docker-fips:
	@test -n "$(BASE_IMAGE)" || (echo "set BASE_IMAGE to a FIPS-enabled Python base image" && exit 1)
	docker build --build-arg FIPS=true --build-arg BASE_IMAGE=$(BASE_IMAGE) -t strongbox:fips .
