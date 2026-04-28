IMAGE_NAME ?= qubership-graylog-auth-proxy
IMAGE_TAG  ?= latest
VENV       := .venv
PYTHON     := $(VENV)/bin/python
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest
COVERAGE   := $(VENV)/bin/coverage

.PHONY: help install test test-coverage build run clean

help:
	@echo "Usage:"
	@echo "  make install        Install all runtime and test dependencies"
	@echo "  make test           Run tests (installs test deps if needed)"
	@echo "  make test-coverage  Run tests with coverage report"
	@echo "  make build          Build Docker image"
	@echo "  make run            Run Docker container (port 8888)"
	@echo "  make clean          Remove venv, __pycache__, and .coverage"

$(VENV)/bin/python:
	python -m venv $(VENV)

# Full runtime install (requires system libs: openldap-dev, gcc)
.install-stamp: $(VENV)/bin/python requirements.txt test-requirements.txt
	$(PIP) install -r requirements.txt -r test-requirements.txt
	@touch .install-stamp

# Test-only install — no C extensions (skips python-ldap)
.test-deps-stamp: $(VENV)/bin/python test-requirements.txt
	$(PIP) install -r test-requirements.txt
	@touch .test-deps-stamp

install: .install-stamp

test: .test-deps-stamp
	$(PYTEST) tests/

test-coverage: .test-deps-stamp
	$(COVERAGE) run -m pytest tests/
	$(COVERAGE) report -m

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

run:
	docker run --rm -p 8888:8888 $(IMAGE_NAME):$(IMAGE_TAG)

clean:
	rm -rf $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -f .coverage .install-stamp .test-deps-stamp
