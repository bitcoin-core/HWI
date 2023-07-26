#! /bin/bash

set -ex

pushd hwilib/ui
for file in *.ui
do
    gen_file=ui_`echo $file| cut -d. -f1`.py
    pyside6-uic $file -o $gen_file
done
popd
