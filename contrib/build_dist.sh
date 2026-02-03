#! /bin/bash
# Script for building pypi distribution archives deterministically
# Usage: First script parameter can be `--without-gui` to build without UI support

set -ex

PYTHON_VERSION=3.10.16

eval "$(pyenv init --path)"
eval "$(pyenv virtualenv-init -)"
export PYENV_VERSION="$PYTHON_VERSION"
pip install -U pip
pip install poetry

gui_support="${1:---with-gui}";

# Setup poetry and install the dependencies
if [[ $gui_support == "--with-gui" ]]; then
    poetry install -E qt
else
    poetry install
fi

# Make the distribution archives for pypi
poetry build -f wheel
# faketime is needed to make sdist deterministic
TZ=UTC faketime -f "2026-01-01 00:00:00" poetry build -f sdist
