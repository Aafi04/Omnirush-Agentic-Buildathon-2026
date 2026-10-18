.PHONY: test build run
PYTHON ?= .venv/bin/python
test:
	$(PYTHON) scripts/test.py
build:
	npm run build
run:
	$(PYTHON) -m uvicorn agenttrace.api:app --app-dir backend --host 127.0.0.1 --port 8000
