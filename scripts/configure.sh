#!/usr/bin/bash

if [[ ! -d "venv" ]]; then
  echo "venv not found, installing..."
  python3 -m virtualenv venv
fi

echo "Installing requirements..."

source venv/bin/activate
python -m pip install -U pip
python -m pip install -r dev_requirements.pip
python -m pip install -r requirements.pip

echo "Installation done."
