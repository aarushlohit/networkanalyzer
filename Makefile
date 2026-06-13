.PHONY: help install dev test lint scan clean docker-build docker-run hooks

help:
	@echo "VulnSync — Network Security Auditor"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Installation:"
	@echo "  install       Install vulnsync from source"
	@echo "  dev           Install with dev/test dependencies"
	@echo ""
	@echo "Development:"
	@echo "  test          Run test suite"
	@echo "  lint          Run ruff linter + mypy type checker"
	@echo "  clean         Remove build artifacts and cache"
	@echo ""
	@echo "Scanning:"
	@echo "  scan          Run scan (override with TARGETS= PORTS=)"
	@echo "  quick         Quick top-100 port scan"
	@echo "  web           Web-focused scan (80,443,8080,8443)"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-run    Run scan via Docker"
	@echo ""
	@echo "Git Hooks:"
	@echo "  hooks         Install pre-commit git hook"
	@echo ""
	@echo "Examples:"
	@echo "  make TARGETS='192.168.1.1' PORTS='80,443' scan"
	@echo "  make TARGETS='10.0.0.0/24' profile=quick quick"
	@echo "  make docker-build && make docker-run TARGETS='example.com'"

PIP := pip
PYTHON := python

install:
	$(PIP) install --upgrade pip
	$(PIP) install -e .

dev:
	$(PIP) install -e ".[dev,test]"

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

lint:
	ruff check .
	$(PYTHON) -m mypy vulnsync/ --ignore-missing-imports

scan:
	vulnsync scan $(TARGETS) -p "$(PORTS)" $(ARGS)

quick:
	vulnsync scan $(TARGETS) --top-ports 100 -p "" --threads 100 $(ARGS)

web:
	vulnsync scan $(TARGETS) -p "80,443,8080,8443,3000,5000" --web-fingerprint $(ARGS)

clean:
	rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	echo "Cleaned build artifacts"

docker-build:
	docker build -t vulnsync:latest -f Dockerfile .

docker-run:
	docker run --network host -v $(PWD)/reports:/home/vulnsync/reports \
		vulnsync:latest scan $(TARGETS) -p "$(PORTS)" -oJ /home/vulnsync/reports/scan.json $(ARGS)

hooks:
	bash scripts/install-hooks.sh
