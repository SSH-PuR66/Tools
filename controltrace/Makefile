.PHONY: install dev lint type test coverage run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check src tests

type:
	mypy src

test:
	pytest

coverage:
	pytest --cov=controltrace --cov-report=term-missing

run:
	controltrace --rules rules --output-dir reports

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info logs
