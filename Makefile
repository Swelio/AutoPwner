.DEFAULT_GOAL := help

configure:
	scripts/configure.sh

lint: venv
	. venv/bin/activate
	black src/
	flake8 src/

help:
	echo "make <configure|lint|run>"