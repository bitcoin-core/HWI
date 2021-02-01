FROM python:3.6

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
