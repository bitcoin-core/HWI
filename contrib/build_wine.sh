#!/bin/bash
# Script which sets up Wine and builds the Windows standalone binary

set -ex

# No Windows installer for 3.6.12
PYTHON_VERSION=3.6.8

PYTHON_FOLDER="python3"
PYHOME="c:/$PYTHON_FOLDER"
PYTHON="wine $PYHOME/python.exe -OO -B"

LIBUSB_VERSION=1.0.23
LIBUSB_URL=https://github.com/libusb/libusb/releases/download/v1.0.23/libusb-1.0.23.tar.bz2
LIBUSB_HASH="db11c06e958a82dac52cf3c65cb4dd2c3f339c8a988665110e0d24d19312ad8d"

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

# Get and build libusb
wget -N -c -O libusb.tar.bz2 "$LIBUSB_URL"
echo "$LIBUSB_HASH  libusb.tar.bz2" | sha256sum -c
tar -xf libusb.tar.bz2
pushd "libusb-$LIBUSB_VERSION"
./configure --host=x86_64-w64-mingw32
faketime -f "2019-01-01 00:00:00" make
cp libusb/.libs/libusb-1.0.dll ~/.wine/drive_c/python3/
popd
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
$POETRY install -E qt

# make the ui files
pushd hwilib/ui
for file in *.ui
do
    gen_file=ui_`echo $file| cut -d. -f1`.py
    $POETRY run pyside2-uic $file -o $gen_file
    sed -i 's/raise()/raise_()/g' $gen_file
done
popd

# Do the build
export PYTHONHASHSEED=42
$POETRY run pyinstaller hwi.spec
$POETRY run pyinstaller hwi-qt.spec
unset PYTHONHASHSEED

# Make the final compressed package
pushd dist
VERSION=`$POETRY run hwi --version | cut -d " " -f 2 | dos2unix`
target_zipfile="hwi-${VERSION}-windows-amd64.zip"
zip $target_zipfile hwi.exe hwi-qt.exe

# Copy the binaries to subdir for shasum
target_dir="$target_zipfile.dir"
mkdir $target_dir
mv hwi.exe $target_dir
mv hwi-qt.exe $target_dir

popd
