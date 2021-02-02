#! /usr/bin/env bash

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

# Clone bitcoind if it doesn't exist, or update it if it does
bitcoind_setup_needed=false
if [ ! -d "bitcoin" ]; then
    git clone https://github.com/bitcoin/bitcoin.git
    cd bitcoin
    bitcoind_setup_needed=true
else
    cd bitcoin
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
        bitcoind_setup_needed=true
    fi
fi

# Build bitcoind. This is super slow, but it is cached so it runs fairly quickly.
if [ "$bitcoind_setup_needed" == true ] ; then
    ./autogen.sh
    ./configure --with-incompatible-bdb --with-miniupnpc=no --without-gui --disable-zmq --disable-tests --disable-bench --with-libs=no --with-utils=no
fi
make src/bitcoind
