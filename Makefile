configure: | venv
	scripts/configure.sh

lint: venv
	source venv/bin/activate
	black src/
	flake8 src/
