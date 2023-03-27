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
        --onekey-1)
        build_onekey_1=1
        shift
        ;;
        --onekey-t)
        build_onekey_t=1
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
        --ledger-legacy)
        build_ledger=1
        shift
        ;;
        --keepkey)
        build_keepkey=1
        shift
        ;;
        --jade)
        build_jade=1
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
        build_jade=1
        build_bitcoind=1
        build_onekey_1=1
        build_onekey_t=1
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
        poetry run pip install protobuf==3.20.0
        poetry run script/setup
        poetry run script/cibuild
        # Delete any emulator.img file
        find . -name "emulator.img" -exec rm {} \;
        cd ..
    fi

    if [[ -n ${build_trezor_t} ]]; then
        rustup update
        rustup toolchain uninstall nightly
        rustup toolchain install nightly
        rustup default nightly
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

if [[ -n ${build_onekey_1} || -n ${build_onekey_t} ]]; then
    # Clone onekey-firmware if it doesn't exist, or update it if it does
    if [ ! -d "onekey-firmware" ]; then
            git clone --recursive https://github.com/OneKeyHQ/firmware.git onekey-firmware
        cd onekey-firmware
    else
        cd onekey-firmware
        git fetch
    fi
    git config pull.rebase true
    # # Remove .venv so that poetry can symlink everything correctly
    find . -type d -name ".venv" -exec rm -rf {} +

    if [[ -n ${build_onekey_1} ]]; then
        # Build trezor one emulator. This is pretty fast, so rebuilding every time is ok
        # But there should be some caching that makes this faster
        git checkout bixin_dev
        git checkout .
        git pull origin bixin_dev
        poetry install
        poetry run pip install protobuf==3.20.0
        export EMULATOR=1 DEBUG_LINK=1 TREZOR_TRANSPORT_V1=1 
        poetry run legacy/script/setup
        poetry run legacy/script/cibuild
        # Delete any emulator.img file
        find . -name "emulator.img" -exec rm {} \;
    fi

    if [[ -n ${build_onekey_t} ]]; then
        rustup update
        rustup toolchain uninstall nightly
        rustup toolchain install nightly
        rustup default nightly
        # Build trezor t emulator. This is pretty fast, so rebuilding every time is ok
        # But there should be some caching that makes this faster
        git checkout touch
        git checkout .
        git pull origin touch
        git submodule update --init --recursive vendor/lvgl_mp
        poetry install
        cd core
        poetry run make build_unix
        # Delete any emulator.img file
        find . -name "onekey.flash" -exec rm {} \;
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
    cmake .. -DBUILD_TYPE=simulator -DCMAKE_C_FLAGS="-Wno-format-truncation -Wno-array-parameter"
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
        cd deps/googletest
        git reset --hard HEAD~1 # Undo git-am for checking and updating
        cd ../..
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
    # Apply patches to make simulator build
    git am ../../data/keepkey-build.patch
    cd deps/googletest
    git am ../../../../data/keepkey-googletest.patch
    cd ../../

    # Build the simulator. This is cached, but it is also fast
    if [ "$keepkey_setup_needed" == true ] ; then
        git clean -ffdx
        git clone https://github.com/nanopb/nanopb.git -b nanopb-0.3.9.4
    fi
    cd nanopb/generator/proto
    make
    cd ../../../
    export PATH=$PATH:`pwd`/nanopb/generator
    cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DPROTOC_BINARY=/usr/local/bin/protoc
    make
    # Delete any emulator.img file
    find . -name "emulator.img" -exec rm {} \;
    cd ..
fi

if [[ -n ${build_ledger} ]]; then
    speculos_packages="construct flask-restful jsonschema mnemonic pyelftools pillow requests pytesseract"
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
    cmake -Bbuild -S .
    make -C build/
    cd ..
fi

if [[ -n ${build_jade} ]]; then
    mkdir -p jade
    cd jade

    # Clone Blockstream Jade firmware if it doesn't exist, or update it if it does
    if [ ! -d "jade" ]; then
        git clone --recursive --branch master https://github.com/Blockstream/Jade.git ./jade
        cd jade
    else
        cd jade
        git fetch --tags --recurse-submodules

        # Determine if we need to pull. From https://stackoverflow.com/a/3278427
        UPSTREAM=${1:-'@{u}'}
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse "$UPSTREAM")
        BASE=$(git merge-base @ "$UPSTREAM")

        if [ $LOCAL = $REMOTE ]; then
            echo "Jade master up-to-date"
        elif [ $LOCAL = $BASE ]; then
            git pull
        fi
        git submodule update --recursive --init
    fi

    # Deduce the relevant versions of esp-idf and qemu to use
    ESP_IDF_BRANCH=$(grep "ARG ESP_IDF_BRANCH=" Dockerfile | cut -d\= -f2)
    ESP_IDF_COMMIT=$(grep "ARG ESP_IDF_COMMIT=" Dockerfile | cut -d\= -f2)
    ESP_QEMU_BRANCH=$(grep "ARG ESP_QEMU_BRANCH=" Dockerfile | cut -d\= -f2)
    ESP_QEMU_COMMIT=$(grep "ARG ESP_QEMU_COMMIT=" Dockerfile | cut -d\= -f2)
    cd ..

    # Build the qemu emulator if required

    # If the directory exists, see if it is at the expected commit
    # If not, remove the entire directory (it will be re-cloned below)
    if [ -d "qemu" ]; then
        cd qemu
        LOCAL=$(git rev-parse @)
        if [ $LOCAL = $ESP_QEMU_COMMIT ]; then
            echo "esp-qemu up-to-date"
            cd ..
        else
            cd ..
            rm -fr qemu
        fi
    fi

    # Clone the upstream if the directory does not exist
    # Then build the emulator
    if [ ! -d "qemu" ]; then
        git clone --depth 1 --branch ${ESP_QEMU_BRANCH} --single-branch --recursive https://github.com/espressif/qemu.git ./qemu
        cd qemu

        git checkout ${ESP_QEMU_COMMIT}
        git submodule update --recursive --init
        ./configure \
            --target-list=xtensa-softmmu \
            --enable-gcrypt \
            --disable-sanitizers \
            --disable-strip \
            --disable-user \
            --disable-capstone \
            --disable-vnc \
            --disable-sdl \
            --disable-gtk \
            --enable-slirp \
            --extra-cflags=-Wno-array-parameter
        ninja -C build
        cd ..
    fi

    # Build the esp-idf toolchain if required

    # We will install the esp-idf tools in a given location (otherwise defaults to user home dir)
    export IDF_TOOLS_PATH="$(pwd)/esp-idf-tools"

    # If the directory exists, see if it is at the expected commit
    # If not, remove the entire directory (it will be re-cloned below)
    if [ -d "esp-idf" ]; then
        cd esp-idf
        LOCAL=$(git rev-parse @)
        if [ $LOCAL = $ESP_IDF_COMMIT ]; then
            echo "esp-idf up-to-date"
            cd ..
        else
            cd ..
            rm -fr esp-idf
        fi
    fi

    # Clone the upstream if the directory does not exist
    # Then build and install the tools
    if [ ! -d "esp-idf" ]; then
        git clone --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive https://github.com/espressif/esp-idf.git ./esp-idf
        cd esp-idf

        git checkout ${ESP_IDF_COMMIT}
        git submodule update --recursive --init
        cd ..
    fi

    # Install the tools every run regardless
    # (Otherwise a cached CI run which skips the above esp-idf clone does not
    # always seem to pick up the locally installed python virtualenv, and instead uses
    # the system python/no-virtualenv which fails ...)
    # Only install the tools we need (ie. esp32)
    rm -fr "${IDF_TOOLS_PATH}"
    cd esp-idf
    ./install.sh esp32
    cd ..

    # Export the tools
    . ./esp-idf/export.sh

    # Build Blockstream Jade firmware configured for the emulator
    cd jade
    rm -fr sdkconfig
    cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
    idf.py fullclean all

    # Make the qemu flash image
    esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o main/qemu/flash_image.bin \
    --flash_mode dio --flash_freq 40m --flash_size 4MB \
    0x9000 build/partition_table/partition-table.bin \
    0xe000 build/ota_data_initial.bin \
    0x1000 build/bootloader/bootloader.bin \
    0x10000 build/jade.bin
    cd ..

    # Extract the minimal artifacts required to run the emulator
    rm -fr simulator
    mkdir simulator
    cp qemu/build/qemu-system-xtensa simulator/
    cp -R qemu/pc-bios simulator/
    cp jade/main/qemu/flash_image.bin simulator/
    cp jade/main/qemu/qemu_efuse.bin simulator/

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
        git reset --hard origin/master
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

    # Do the build
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --with-incompatible-bdb --with-miniupnpc=no --without-gui --disable-zmq --disable-tests --disable-bench --with-libs=no --with-utils=no
    make src/bitcoind
fi
