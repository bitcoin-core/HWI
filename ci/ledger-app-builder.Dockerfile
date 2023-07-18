# Copied from https://github.com/LedgerHQ/ledger-app-builder/blob/229b03cf20630e6bdc66d7f1ce33c70b2fd2b9e5/Dockerfile

# Cache break (modify this line to break cirrus' dockerfile build cache) 1

FROM ubuntu:20.04
ENV LANG C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive

ARG LLVM_VERSION=12

RUN apt-get update && apt-get upgrade -qy && \
    apt-get install -qy \
        clang-$LLVM_VERSION \
        clang-tools-$LLVM_VERSION \
        clang-format-$LLVM_VERSION \
        cmake \
        curl \
        doxygen \
        git \
        lcov \
        libbsd-dev \
        libcmocka0 \
        libcmocka-dev \
        lld-$LLVM_VERSION \
        make \
        protobuf-compiler \
        python-is-python3 \
        python3 \
        python3-pip && \
    apt-get autoclean -y && \
    apt-get autoremove -y && \
    apt-get clean

# Create generic clang & lld symbolic links to their installed version
RUN cd /usr/bin && \
    find . -name "*-"$LLVM_VERSION | sed "s/^\(.*\)\(-"$LLVM_VERSION"\)$/ln -s \1\2 \1/" | sh

# ARM Embedded Toolchain
# Integrity is checked using the MD5 checksum provided by ARM at https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads
RUN curl -sSfL -o arm-toolchain.tar.bz2 "https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-x86_64-linux.tar.bz2" && \
    echo 2383e4eb4ea23f248d33adc70dc3227e arm-toolchain.tar.bz2 > /tmp/arm-toolchain.md5 && \
    md5sum --check /tmp/arm-toolchain.md5 && rm /tmp/arm-toolchain.md5 && \
    tar xf arm-toolchain.tar.bz2 -C /opt && \
    rm arm-toolchain.tar.bz2

# Adding GCC to PATH and defining rustup/cargo home directories
ENV PATH=/opt/gcc-arm-none-eabi-10.3-2021.10/bin:$PATH \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/.cargo

# Install rustup to manage rust toolchains
RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain stable -y

# Adding cargo binaries to PATH
ENV PATH=${CARGO_HOME}/bin:${PATH}

# Adding ARMV6M target to the default toolchain
RUN rustup target add thumbv6m-none-eabi

# Python packages commonly used by apps
RUN pip3 install ledgerblue pytest

# Latest Nano S SDK
ENV NANOS_SDK=/opt/nanos-secure-sdk
RUN git clone --branch 2.1.0 --depth 1 https://github.com/LedgerHQ/nanos-secure-sdk.git "${NANOS_SDK}"

# Latest Nano X SDK
ENV NANOX_SDK=/opt/nanox-secure-sdk
RUN git clone --branch 2.0.2-2 --depth 1 https://github.com/LedgerHQ/nanox-secure-sdk.git "${NANOX_SDK}"

# Latest Nano S+ SDK
ENV NANOSP_SDK=/opt/nanosplus-secure-sdk
RUN git clone --branch 1.0.2 --depth 1 https://github.com/LedgerHQ/nanosplus-secure-sdk.git "${NANOSP_SDK}"

# Default SDK
ENV BOLOS_SDK=${NANOS_SDK}

WORKDIR /app

CMD ["/usr/bin/env", "bash"]
