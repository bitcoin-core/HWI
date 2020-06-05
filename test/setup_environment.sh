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
    pipenv sync
    pipenv run script/setup
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
# Remove nanopb to avoid interfering with keepkey
pip uninstall -y nanopb

# Clone coldcard firmware if it doesn't exist, or update it if it does
coldcard_setup_needed=false
if [ ! -d "firmware" ]; then
    git clone --recursive https://github.com/Coldcard/firmware.git
    cd firmware
    coldcard_setup_needed=true
else
    cd firmware
    git reset --hard HEAD~2 # Undo git-am for checking and updating
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
git am ../../data/coldcard-multisig-setup.patch

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
    git clone https://github.com/nanopb/nanopb.git -b nanopb-0.3.9.4
fi
cd nanopb/generator/proto
make
cd ../../../
export PATH=$PATH:`pwd`/nanopb/generator
cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DPROTOC_BINARY=/usr/bin/protoc
make -j$(nproc) kkemu
# Delete any emulator.img file
find . -name "emulator.img" -exec rm {} \;
cd ..

# Clone ledger simulator Speculos if it doesn't exist, or update it if it does
speculos_setup_needed=false
if [ ! -d "speculos" ]; then
    git clone --recursive https://github.com/LedgerHQ/speculos.git
    cd speculos
    speculos_setup_needed=true
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
        speculos_setup_needed=true
    fi
fi
# Apply patch to get screen info
git am ../../data/speculos-auto-button.patch

# Build the simulator. This is cached, but it is also fast
mkdir -p build
cmake -Bbuild -H.
make -C build/ emu launcher
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
git am ../../data/psbt_non_witness_utxo_segwit.patch

# Build bitcoind. This is super slow, but it is cached so it runs fairly quickly.
if [ "$bitcoind_setup_needed" == true ] ; then
    ./autogen.sh
    ./configure --with-incompatible-bdb --with-miniupnpc=no --without-gui --disable-zmq --disable-tests --disable-bench --with-libs=no --with-utils=no
fi
make -j$(nproc) src/bitcoind
