PYTHON ?= .venv/bin/python
HOST ?= 127.0.0.1
PORT ?= 8080

.PHONY: install run test coverage smoke

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

run:
	$(PYTHON) main.py --host $(HOST) --port $(PORT)

test:
	$(PYTHON) -m pytest -q

coverage:
	$(PYTHON) -m coverage run -m pytest -q
	$(PYTHON) -m coverage report -m

smoke:
	$(PYTHON) scripts/smoke_test.py
