.DEFAULT_GOAL := help

configure:
	scripts/configure.sh

lint: venv
	. venv/bin/activate
	isort src/
	black src/
	flake8 src/

check-lint: venv
	. venv/bin/activate
	isort --check-only src/
	black --check src/
	flake8 src/

help:
	echo "make <configure|lint|check-lint>"