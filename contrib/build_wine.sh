#!/bin/bash
# Script which sets up Wine and builds the Windows standalone binary

set -ex

# Note: Python MSIs/EXEs are no longer hosted for 3.10.x on python.org.
# The NuGet python package currently only goes up to 3.10.11, so Windows builds use that.
PYTHON_VERSION=3.10.11
PYTHON_NUGET_URL="https://api.nuget.org/v3-flatcontainer/python/${PYTHON_VERSION}/python.${PYTHON_VERSION}.nupkg"
PYTHON_NUGET_HASH="7c6f99b160a36a7e09492dfcff2b0a3a60bb5229ca44cdcc3ecb32871a6144d0"

PYTHON_FOLDER="python3"
PYHOME="c:/$PYTHON_FOLDER"
PYTHON="wine $PYHOME/python.exe -OO -B"

LIBUSB_VERSION=1.0.26
LIBUSB_URL=https://github.com/libusb/libusb/releases/download/v${LIBUSB_VERSION}/libusb-${LIBUSB_VERSION}.tar.bz2
LIBUSB_HASH="12ce7a61fc9854d1d2a1ffe095f7b5fac19ddba095c259e6067a46500381b5a5"

WINDOWS_SDK_URL=http://go.microsoft.com/fwlink/p/?LinkID=2033686
WINDOWS_SDK_HASH="016981259708e1afcab666c7c1ff44d1c4d63b5e778af8bc41b4f6db3d27961a"
WINDOWS_SDK_VERSION=10.0.17763.0

wine 'wineboot'

# Install Python from NuGet package
wget -O python.nupkg -N -c "$PYTHON_NUGET_URL"
echo "$PYTHON_NUGET_HASH  python.nupkg" | sha256sum -c
rm -rf python-nupkg
7z x python.nupkg -opython-nupkg >/dev/null
rm -rf ~/.wine/drive_c/python3
mkdir -p ~/.wine/drive_c/python3
cp -a python-nupkg/tools/* ~/.wine/drive_c/python3/
rm -rf python.nupkg python-nupkg

# Get and build libusb
wget -N -c -O libusb.tar.bz2 "$LIBUSB_URL"
echo "$LIBUSB_HASH  libusb.tar.bz2" | sha256sum -c
tar -xf libusb.tar.bz2
pushd "libusb-$LIBUSB_VERSION"
./configure --host=x86_64-w64-mingw32
faketime -f "2026-01-01 00:00:00" make
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
TZ=UTC find ${lib_dir} -name '*.py' -type f -execdir touch -t "202601010000.00" '{}' \;

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
target_zipfile="hwi-${VERSION}-windows-x86_64.zip"
zip $target_zipfile hwi.exe hwi-qt.exe

# Copy the binaries to subdir for shasum
target_dir="$target_zipfile.dir"
mkdir $target_dir
mv hwi.exe $target_dir
mv hwi-qt.exe $target_dir

popd
