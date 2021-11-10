FROM python:3.8

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    cython3 \
    git \
    libsdl2-dev \
    libsdl2-image-dev \
    libudev-dev \
    libusb-1.0-0-dev \
    qemu-user-static

RUN pip install poetry flake8

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
