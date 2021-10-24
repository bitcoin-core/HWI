#! /usr/bin/env bash

while [[ $# -gt 0 ]]; do
    case $1 in
        --trezor-1)
        build_trezor_1=1
        shift
        ;;
        --trezor-t)
        build_trezor_t=1
        shift
        ;;
        --coldcard)
        build_coldcard=1
        shift
        ;;
        --bitbox01)
        build_bitbox01=1
        shift
        ;;
        --ledger)
        build_ledger=1
        shift
        ;;
        --keepkey)
        build_keepkey=1
        shift
        ;;
        --bitcoind)
        build_bitcoind=1
        shift
        ;;
        --all)
        build_trezor_1=1
        build_trezor_t=1
        build_coldcard=1
        build_bitbox01=1
        build_ledger=1
        build_keepkey=1
        build_bitcoind=1
        shift
        ;;
    esac
done

# Makes debugging easier
set -ex

# Go into the working directory
mkdir -p work
cd work

if [[ -n ${build_trezor_1} || -n ${build_trezor_t} ]]; then
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

    if [[ -n ${build_trezor_1} ]]; then
        # Build trezor one emulator. This is pretty fast, so rebuilding every time is ok
        # But there should be some caching that makes this faster
        poetry install
        cd legacy
        export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
        poetry run script/setup
        poetry run script/cibuild
        # Delete any emulator.img file
        find . -name "emulator.img" -exec rm {} \;
        cd ..
    fi

    if [[ -n ${build_trezor_t} ]]; then
        rustup toolchain uninstall stable
        rustup toolchain install stable
        rustup update
        # Build trezor t emulator. This is pretty fast, so rebuilding every time is ok
        # But there should be some caching that makes this faster
        poetry install
        cd core
        poetry run make build_unix
        # Delete any emulator.img file
        find . -name "trezor.flash" -exec rm {} \;
        cd ..
    fi
    cd ..
fi

if [[ -n ${build_coldcard} ]]; then
    # Clone coldcard firmware if it doesn't exist, or update it if it does
    coldcard_setup_needed=false
    if [ ! -d "firmware" ]; then
        git clone --recursive https://github.com/Coldcard/firmware.git
        cd firmware
        coldcard_setup_needed=true
    else
        cd firmware
        git reset --hard HEAD~3 # Undo git-am for checking and updating
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
    git am ../../data/coldcard-multisig.patch

    # Apply patch to libngu to make it compile
    pushd external/libngu
    git am ../../../../data/coldcard-libngu.patch
    popd

    # Build the simulator. This is cached, but it is also fast
    poetry run pip install -r requirements.txt
    pip install -r requirements.txt
    cd unix
    if [ "$coldcard_setup_needed" == true ] ; then
        pushd ../external/micropython/mpy-cross/
        make
        popd
        make setup
        make ngu-setup
    fi
    make
    cd ../..
fi

if [[ -n ${build_bitbox01} ]]; then
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
fi

if [[ -n ${build_keepkey} ]]; then
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
        git reset --hard HEAD~1 # Undo git-am for checking and updating
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
    # Apply patch to make simulator build
    git am ../../data/keepkey-build.patch

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
fi

if [[ -n ${build_ledger} ]]; then
    speculos_packages="construct flask-restful jsonschema mnemonic pyelftools pillow requests"
    poetry run pip install ${speculos_packages}
    pip install ${speculos_packages}
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
    make -C build/ emu launcher copy-launcher
    cd ..
fi

if [[ -n ${build_bitcoind} ]]; then
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
    pushd depends
    make NO_QT=1 NO_QR=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1
    popd
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --with-incompatible-bdb --with-miniupnpc=no --without-gui --disable-zmq --disable-tests --disable-bench --with-libs=no --with-utils=no
    make src/bitcoind
fi
