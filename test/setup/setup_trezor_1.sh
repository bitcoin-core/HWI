#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

# Clone trezor-firmware if it doesn't exist, or update it if it does
if [ ! -d "trezor-firmware" ]; then
    git clone --recursive https://github.com/trezor/trezor-firmware.git
    cd trezor-firmware
else
    cd trezor-firmware
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

# Remove .venv so that poetry can symlink everything correctly
find . -type d -name ".venv" -exec rm -rf {} +

# Build trezor one emulator. This is pretty fast, so rebuilding every time is ok
# But there should be some caching that makes this faster
poetry install
cd legacy
export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
poetry run script/setup
poetry run script/cibuild
# Delete any emulator.img file
find . -name "emulator.img" -exec rm {} \;
cd ../..
