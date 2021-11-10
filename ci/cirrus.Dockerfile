FROM python:3.6

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    autotools-dev \
    automake \
    bsdmainutils \
    build-essential \
    ccache \
    clang \    
    cmake \
    curl \
    cython3 \
    gcc-arm-none-eabi \
    gcc-arm-linux-gnueabihf \
    git \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libc6-dev-armhf-cross \
    libdb-dev \
    libdb++-dev \
    libevent-dev \
    libnewlib-arm-none-eabi \
    libsdl2-dev \
    libsdl2-image-dev \
    libssl-dev \
    libtool \
    libudev-dev \
    libusb-1.0-0-dev \
    pkg-config \
    protobuf-compiler \
    qemu-user-static

RUN pip install poetry flake8
RUN wget https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
RUN chmod +x rustup-init && ./rustup-init -y
ENV PATH="/root/.cargo/bin:$PATH"

####################
# Local build/test steps
# -----------------
# To install all simulators/tests locally, uncomment the block below,
# then build the docker image and interactively run the tests
# as needed.
# e.g.,
# docker build -f ci/cirrus.Dockerfile -t hwi_test .
# docker run -it --entrypoint /bin/bash hwi_tst
# cd test; poetry run ./run_tests.py --ledger --coldcard --interface=cli --device-only
####################

####################
#ENV EMAIL=email
#COPY pyproject.toml pyproject.toml
#RUN poetry run pip install construct pyelftools mnemonic jsonschema
#
## Set up environments first to take advantage of layer caching
#RUN mkdir test
#COPY test/setup_environment.sh test/setup_environment.sh
#COPY test/data/coldcard-multisig.patch test/data/coldcard-multisig.patch
## One by one to allow for intermediate caching of successful builds
#RUN cd test; ./setup_environment.sh --trezor-1
#RUN cd test; ./setup_environment.sh --trezor-t
#RUN cd test; ./setup_environment.sh --coldcard
#RUN cd test; ./setup_environment.sh --bitbox01
#RUN cd test; ./setup_environment.sh --ledger
#RUN cd test; ./setup_environment.sh --keepkey
#RUN cd test; ./setup_environment.sh --bitcoind
#
## Once everything has been built, put rest of files in place
## which have higher turn-over.
#COPY test/ test/
#COPY hwi.py hwi-qt.py README.md /
#COPY hwilib/ /hwilib/
#RUN poetry install
#
####################

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
