docker volume rm bitbox02_volume || true
docker volume create bitbox02_volume
CONTAINER_VERSION=$(curl https://raw.githubusercontent.com/BitBoxSwiss/bitbox02-firmware/master/.containerversion)
docker pull shiftcrypto/firmware_v2:$CONTAINER_VERSION
docker run -i --rm -v bitbox02_volume:/bitbox02-firmware shiftcrypto/firmware_v2:$CONTAINER_VERSION bash -c \
    "cd /bitbox02-firmware && \
    git clone --recursive https://github.com/BitBoxSwiss/bitbox02-firmware.git . && \
    git config --global --add safe.directory ./ && \
    make -j simulator"