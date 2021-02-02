#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

# Clone digital bitbox firmware if it doesn't exist, or update it if it does
if [ ! -d "mcu" ]; then
    git clone --recursive https://github.com/digitalbitbox/mcu.git
    cd mcu
else
    cd mcu
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
mkdir -p build && cd build
cmake .. -DBUILD_TYPE=simulator -DCMAKE_C_FLAGS="-Wno-format-truncation"
make
cd ../..
