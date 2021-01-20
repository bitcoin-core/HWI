FROM python:3.7

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    autotools-dev \
    automake \
    cmake \
    pkg-config \
    bsdmainutils \
    libtool \
    curl \
    git \
    ccache \
    qemu-user-static \
    libsdl2-dev \
    libsdl2-image-dev \
    gcc-arm-none-eabi \
    libnewlib-arm-none-eabi \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross \
    libudev-dev \
    libusb-1.0-0-dev \
    libssl-dev \
    libevent-dev \
    libdb-dev \
    libdb++-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-test-dev \
    libboost-thread-dev \
    protobuf-compiler \
    cython3
RUN pip install poetry flake8
