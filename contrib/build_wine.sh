#!/bin/bash
# Script which sets up Wine and builds the Windows standalone binary

set -e

PYTHON_VERSION=3.6.8

PYTHON_FOLDER="python3"
PYHOME="c:/$PYTHON_FOLDER"
PYTHON="wine $PYHOME/python.exe -OO -B"

LIBUSB_URL=https://github.com/libusb/libusb/releases/download/v1.0.22/libusb-1.0.22.7z
LIBUSB_HASH="671f1a420757b4480e7fadc8313d6fb3cbb75ca00934c417c1efa6e77fb8779b"

WINDOWS_SDK_URL=http://go.microsoft.com/fwlink/p/?LinkID=2033686
WINDOWS_SDK_HASH="016981259708e1afcab666c7c1ff44d1c4d63b5e778af8bc41b4f6db3d27961a"
WINDOWS_SDK_VERSION=10.0.17763.0

wine 'wineboot'

# Install Python
# Get the PGP keys
wget -N -c "https://www.python.org/static/files/pubkeys.txt"
gpg --import pubkeys.txt
rm pubkeys.txt

# Install python components
for msifile in core dev exe lib pip tools; do
    wget -N -c "https://www.python.org/ftp/python/$PYTHON_VERSION/amd64/${msifile}.msi"
    wget -N -c "https://www.python.org/ftp/python/$PYTHON_VERSION/amd64/${msifile}.msi.asc"
    gpg --verify "${msifile}.msi.asc" "${msifile}.msi"
    wine msiexec /i "${msifile}.msi" /qb TARGETDIR=$PYHOME
    rm $msifile.msi*
done

# Get libusb
wget -N -c -O libusb.7z "$LIBUSB_URL"
echo "$LIBUSB_HASH  libusb.7z" | sha256sum -c
7za x -olibusb libusb.7z -aoa
cp libusb/MS64/dll/libusb-1.0.dll ~/.wine/drive_c/python3/
rm -r libusb*

# Get the Windows SDK
pushd `mktemp -d`
wget -O sdk.iso "$WINDOWS_SDK_URL"
echo "$WINDOWS_SDK_HASH  sdk.iso" | sha256sum -c
7z e sdk.iso
wine msiexec /i "Universal CRT Redistributable-x86_en-us.msi"
cp ~/.wine/drive_c/Program\ Files\ \(x86\)/Windows\ Kits/10/Redist/${WINDOWS_SDK_VERSION}/ucrt/DLLs/x64/*.dll ~/.wine/drive_c/windows/system32/
popd

# Update pip
$PYTHON -m pip install -U pip

# Install Poetry and things needed for pyinstaller
$PYTHON -m pip install poetry

# We also need to change the timestamps of all of the base library files
lib_dir=~/.wine/drive_c/python3/Lib
TZ=UTC find ${lib_dir} -name '*.py' -type f -execdir touch -t "201901010000.00" '{}' \;

# Install python dependencies
POETRY="wine $PYHOME/Scripts/poetry.exe"
sleep 5 # For some reason, pausing for a few seconds makes the next step work
$POETRY install -E windist

# Do the build
export PYTHONHASHSEED=42
$POETRY run pyinstaller hwi.spec
unset PYTHONHASHSEED
