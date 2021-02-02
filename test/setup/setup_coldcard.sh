#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

# Clone coldcard firmware if it doesn't exist, or update it if it does
coldcard_setup_needed=false
if [ ! -d "firmware" ]; then
    git clone --recursive https://github.com/Coldcard/firmware.git
    cd firmware
    coldcard_setup_needed=true
else
    cd firmware
    git reset --hard HEAD~2 # Undo git-am for checking and updating, see below incantation
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
        coldcard_setup_needed=true

    fi
fi

if [ "$coldcard_setup_needed" == true ] ; then
    # Apply patch to make simulator work in linux environments
    git am ../../data/coldcard-multisig.patch
fi

# Build the simulator. This is cached, but it is also fast
poetry run pip install -r requirements.txt
pip install -r requirements.txt
cd unix
if [ "$coldcard_setup_needed" == true ] ; then
    make setup
fi
make
cd ../..
