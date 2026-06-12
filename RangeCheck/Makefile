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
	pytest --cov=rangecheck --cov-report=term-missing

run:
	rangecheck 127.0.0.1 --confirm-authorized --ports 22,80,443 --output-dir reports

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info logs
