FROM debian:oldoldstable-slim

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    g++-mingw-w64-x86-64 \
    faketime \
    dos2unix \
    zip \
    wget

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

