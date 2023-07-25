#! /bin/bash
# Script for building standalone binary releases deterministically
# Usage: First script parameter can be `--without-gui` to build without UI support

set -ex

eval "$(pyenv init --path)"
eval "$(pyenv virtualenv-init -)"
pip install -U pip
pip install poetry

gui_support="${1:---with-gui}";

# Setup poetry and install the dependencies
if [[ $gui_support == "--with-gui" ]]; then
    poetry install -E qt
else
    poetry install
fi

# We also need to change the timestamps of all of the base library files
lib_dir=$(pyenv prefix)/lib/python3.9
TZ=UTC find ${lib_dir} -name '*.py' -type f -execdir touch -t "201901010000.00" '{}' \;

# Make the standalone binary
export PYTHONHASHSEED=42
poetry run pyinstaller hwi.spec

if [[ $gui_support == "--with-gui" ]]; then
    poetry run contrib/generate-ui.sh
    poetry run pyinstaller hwi-qt.spec
fi

unset PYTHONHASHSEED

# Make the final compressed package
pushd dist
VERSION=`poetry run hwi --version | cut -d " " -f 2`
OS=`uname | tr '[:upper:]' '[:lower:]'`
if [[ $OS == "darwin" ]]; then
    OS="mac"
fi
ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
target_tarfile="hwi-${VERSION}-${OS}-${ARCH}.tar.gz"

if [[ $gui_support == "--with-gui" ]]; then
    tar -czf $target_tarfile hwi hwi-qt
else
    tar -czf $target_tarfile hwi
fi

# Copy the binaries to subdir for shasum
target_dir="$target_tarfile.dir"
mkdir $target_dir
mv hwi $target_dir

if [[ $gui_support == "--with-gui" ]]; then
    mv hwi-qt $target_dir
fi

popd
