.PHONY: lint
lint:
	ruff check --fix
	ruff format

.PHONY: test
test: main.py
	python3 -m doctest --verbose $^

README.md: main.py
	python3 -c 'import ast; open("$@", "w", encoding="utf-8").write("<!-- Generated from $<'"'"'s module docstring by `make readme`; edit the docstring, not this file. -->\n\n" + ast.get_docstring(ast.parse(open("$<", encoding="utf-8").read())))'