#! /bin/bash

pushd hwilib/ui
for file in *.ui
do
    gen_file=ui_`echo $file| cut -d. -f1`.py
    pyside2-uic $file -o $gen_file
    sed -i 's/raise()/raise_()/g' $gen_file
done
popd
