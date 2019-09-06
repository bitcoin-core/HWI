#! /bin/bash
# Script for building pypi distribution archives deterministically

eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
pip install -U pip
pip install poetry

# Setup poetry and install the dependencies
poetry install

# Make the distribution archives for pypi
poetry build -f wheel
# faketime is needed to make sdist detereministic
TZ=UTC faketime -f "2019-01-01 00:00:00" poetry build -f sdist
