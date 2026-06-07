.PHONY: lint
lint:
	ruff check --fix
	ruff format

.PHONY: test
test: main.py
	python3 -m doctest --verbose $^
