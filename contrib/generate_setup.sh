#! /bin/bash
# Generates the setup.py file

set -ex

# Setup poetry and install the dependencies
poetry install -E qt

# Build the source distribution
poetry build -f sdist

# Extract setup.py from the distribution
unset -v tarball
for file in dist/*
do
    if [[ $file -nt $tarball && $file == *".tar.gz" ]]
    then
        tarball=$file
    fi
done
unset -v toextract
for file in `tar -tf $tarball`
do
    if [[ $file == *"setup.py" ]]
    then
        toextract=$file
    fi
done
tar -xf $tarball $toextract
mv $toextract .
dir=`echo $toextract | cut -f1 -d"/"`
rm -r $dir
sed -i 's/distutils.core/setuptools/g' setup.py
