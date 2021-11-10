#! /bin/bash
# Script for building standalone binary releases deterministically

set -ex

eval "$(pyenv init --path)"
eval "$(pyenv virtualenv-init -)"
pip install -U pip
pip install poetry

# Setup poetry and install the dependencies
poetry install -E qt

# We also need to change the timestamps of all of the base library files
lib_dir=`pyenv root`/versions/3.6.12/lib/python3.6
TZ=UTC find ${lib_dir} -name '*.py' -type f -execdir touch -t "201901010000.00" '{}' \;

# Make the standalone binary
export PYTHONHASHSEED=42
poetry run pyinstaller hwi.spec
poetry run contrib/generate-ui.sh
poetry run pyinstaller hwi-qt.spec
unset PYTHONHASHSEED

# Make the final compressed package
pushd dist
VERSION=`poetry run hwi --version | cut -d " " -f 2`
OS=`uname | tr '[:upper:]' '[:lower:]'`
if [[ $OS == "darwin" ]]; then
    OS="mac"
fi
target_tarfile="hwi-${VERSION}-${OS}-amd64.tar.gz"
tar -czf $target_tarfile hwi hwi-qt

# Copy the binaries to subdir for shasum
target_dir="$target_tarfile.dir"
mkdir $target_dir
mv hwi $target_dir
mv hwi-qt $target_dir

popd
