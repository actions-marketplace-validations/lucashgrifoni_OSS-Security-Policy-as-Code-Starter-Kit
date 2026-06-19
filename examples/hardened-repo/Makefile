# Build-from-source entrypoint for the hardened example fixture.
# Demonstrates documented build instructions (OSPS-DO-07 / GOV-BUILD-072).

.PHONY: build test lint

build:	## Build the project from source.
	python -m build

test:	## Run the test suite.
	pytest

lint:	## Run linters.
	ruff check .
