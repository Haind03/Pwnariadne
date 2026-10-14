# Pwnariadne — top-level developer tasks.
# Author: HaiND from the Post and Telecommunication Institute of Technology

PY ?= python3

.PHONY: help install dev demo test lint run clean

help:
	@echo "Pwnariadne make targets:"
	@echo "  make install   - install the package"
	@echo "  make dev       - install with dev extras (pytest)"
	@echo "  make demo      - build the deliberately-unsafe example binary"
	@echo "  make test      - build the demo and run the test suite"
	@echo "  make run       - analyse the demo binary (terminal report)"
	@echo "  make clean     - remove build artifacts and caches"

install:
	$(PY) -m pip install -e .

dev:
	$(PY) -m pip install -e ".[dev]"

demo:
	$(MAKE) -C examples

test: demo
	$(PY) -m pytest -q

run: demo
	$(PY) -m pwnariadne examples/vuln_demo --gdb examples/demo.gdb

clean:
	$(MAKE) -C examples clean
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
