# Cache break (modify this line to break cirrus' dockerfile build cache) 1

FROM python:3.7

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    cython3 \
    git \
    libpcsclite-dev \
    libsdl2-dev \
    libsdl2-image-dev \
    libudev-dev \
    libusb-1.0-0-dev \
    qemu-user-static \
    swig

RUN pip install poetry flake8

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
