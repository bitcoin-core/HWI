#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

poetry run pip install protobuf
pip install protobuf
# Clone keepkey firmware if it doesn't exist, or update it if it does
keepkey_setup_needed=false
if [ ! -d "keepkey-firmware" ]; then
    git clone --recursive https://github.com/keepkey/keepkey-firmware.git
    cd keepkey-firmware
    keepkey_setup_needed=true
else
    cd keepkey-firmware
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
        keepkey_setup_needed=true
    fi
fi

# Build the simulator. This is cached, but it is also fast
if [ "$keepkey_setup_needed" == true ] ; then
    git clone https://github.com/nanopb/nanopb.git -b nanopb-0.3.9.4
fi
cd nanopb/generator/proto
make
cd ../../../
export PATH=$PATH:`pwd`/nanopb/generator
cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DPROTOC_BINARY=/usr/bin/protoc
make
# Delete any emulator.img file
find . -name "emulator.img" -exec rm {} \;
cd ..
