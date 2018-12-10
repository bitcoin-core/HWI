#! /usr/bin/env bash

# Makes debugging easier
set -x

# Go into the working directory
mkdir -p work
cd work

# Clone trezor-mcu if it doesn't exist, or update it if it does
trezor_setup_needed=false
if [ ! -d "trezor-mcu" ]; then
    git clone --recursive https://github.com/trezor/trezor-mcu.git
    cd trezor-mcu
    trezor_setup_needed=true
else
    cd trezor-mcu
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
        trezor_setup_needed=true
    fi
fi

# Build emulator. This is pretty fast, so rebuilding every time is ok
# But there should be some caching that makes this faster
export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
if [ "$trezor_setup_needed" == true ] ; then
    script/setup
    pipenv install
fi
pipenv run script/cibuild
cd ..

# Clone coldcard firmware if it doesn't exist, or update it if it does
coldcard_setup_needed=false
if [ ! -d "firmware" ]; then
    git clone --recursive https://github.com/Coldcard/firmware.git
    cd firmware
    coldcard_setup_needed=true
else
    cd firmware
    git reset --hard HEAD^ # Undo git-am for checking and updating
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
# Apply patch to make simulator work in linux environments
git am ../../data/coldcard-linux-sock.patch

# Build the simulator. This is cached, but it is also fast
cd unix
if [ "$coldcard_setup_needed" == true ] ; then
    make setup
fi
make -j$(nproc)
cd ../..

# Clone bitcoind if it doesn't exist, or update it if it does
bitcoind_setup_needed=false
if [ ! -d "bitcoin" ]; then
    git clone https://github.com/achow101/bitcoin.git -b hww
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
    ./configure
fi
make -j$(nproc) src/bitcoind
