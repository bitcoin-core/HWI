#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

poetry run pip install construct mnemonic pyelftools jsonschema
pip install construct mnemonic pyelftools jsonschema
# Clone ledger simulator Speculos if it doesn't exist, or update it if it does
if [ ! -d "speculos" ]; then
    git clone --recursive https://github.com/LedgerHQ/speculos.git
    cd speculos
else
    cd speculos
    git fetch

    # Determine if we need to pull. From https://stackoverflow.com/a/3278427
    UPSTREAM=${1:-'@{u}'}
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse "$UPSTREAM")
    BASE=$(git merge-base @ "$UPSTREAM")

    if [ $LOCAL = $REMOTE ]; then
        echo "Up-to-date"
    elif [ $LOCAL = $BASE ]; then
        git pull
    fi
fi

# Build the simulator. This is cached, but it is also fast
mkdir -p build
cmake -Bbuild -H.
make -C build/ emu launcher
cd ..
