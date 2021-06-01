#! /bin/bash
# Script for generating the SHA256SUMS.txt file

set -ex

pushd dist

sums=SHA256SUMS.txt
sum_files=`find . -type f -not -name *$sums* | sort`
sha256sum $sum_files > $sums
sed -i 's/\.\///g' $sums
sed -i 's/\.dir//g' $sums

popd
