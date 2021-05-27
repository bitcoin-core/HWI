FROM debian:stretch-slim

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    apt-transport-https \
    git \
    make \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    wget \
    curl \
    llvm \
    libncurses5-dev \
    xz-utils \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    libusb-1.0-0-dev \
    libudev-dev \
    faketime \
    zip \
    dos2unix \
    g++-mingw-w64-x86-64 \
    qt5-default

RUN curl https://pyenv.run | bash
ENV PYENV_ROOT="/root/.pyenv"
ENV PATH="$PYENV_ROOT/bin:$PATH"

COPY contrib/reproducible-python.diff /opt/reproducible-python.diff
ENV PYTHON_CONFIGURE_OPTS="--enable-shared"
ENV BUILD_DATE="Jan  1 2019"
ENV BUILD_TIME="00:00:00"
RUN eval "$(pyenv init --path)" && eval "$(pyenv virtualenv-init -)" && cat /opt/reproducible-python.diff | pyenv install -kp 3.6.12

RUN dpkg --add-architecture i386
RUN wget -nc https://dl.winehq.org/wine-builds/winehq.key
RUN apt-key add winehq.key
RUN echo "deb https://dl.winehq.org/wine-builds/debian/ stretch main" >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install --install-recommends -y \
    wine-stable-amd64 \
    wine-stable-i386 \
    wine-stable \
    winehq-stable \
    p7zip-full

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
