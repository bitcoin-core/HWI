#! /usr/bin/env bash

# Makes debugging easier
set -x

# Go into the working directory
mkdir -p work
cd work

# Clone trezor-mcu if it doesn't exist, or update it if it does
trezor_setup_needed=false
if [ ! -d "trezor-firmware" ]; then
    git clone --recursive https://github.com/trezor/trezor-firmware.git
    cd trezor-firmware
    trezor_setup_needed=true
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
        trezor_setup_needed=true
    fi
fi

# Build trezor one emulator. This is pretty fast, so rebuilding every time is ok
# But there should be some caching that makes this faster
cd legacy
export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
if [ "$trezor_setup_needed" == true ] ; then
    script/setup
    pipenv install
fi
pipenv run script/cibuild
# Delete any emulator.img file
find . -name "emulator.img" -exec rm {} \;
cd ..

# Build trezor t emulator. This is pretty fast, so rebuilding every time is ok
# But there should be some caching that makes this faster
cd core
if [ "$trezor_setup_needed" == true ] ; then
    make vendor
fi
make build_unix
# Delete any emulator.img file
rm /var/tmp/trezor.flash
cd ../..

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

# Clone digital bitbox firmware if it doesn't exist, or update it if it does
dbb_setup_needed=false
if [ ! -d "mcu" ]; then
    git clone --recursive https://github.com/digitalbitbox/mcu.git
    cd mcu
    dbb_setup_needed=true
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
        coldcard_setup_needed=true
    fi
fi

# Build the simulator. This is cached, but it is also fast
mkdir -p build && cd build
cmake .. -DBUILD_TYPE=simulator
make -j$(nproc)
cd ../..

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
    git clone https://github.com/nanopb/nanopb.git -b nanopb-0.2.9.2
fi
# This needs py2, so make a pipenv
export PIPENV_IGNORE_VIRTUALENVS=1
pipenv --python 2.7
pipenv install protobuf
cd nanopb/generator/proto
pipenv run make
cd ../../../
export PATH=$PATH:`pwd`/nanopb/generator
pipenv run cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DKK_HAVE_STRLCAT=OFF -DKK_HAVE_STRLCPY=OFF
pipenv run make -j$(nproc) kkemu
# Delete any emulator.img file
find . -name "emulator.img" -exec rm {} \;
cd ..

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
make -j$(nproc) src/bitcoind
