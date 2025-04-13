#!/bin/bash

# 该模块从deb还原theos工程

if [ x$1 == x ]; then
    echo Usage: $0 test.deb
    exit 0
fi

root=$(dirname $0)
debpath=$1
debfile=$(basename $debpath)
debname=${debfile%.*}

if [[ ! $debfile =~ ".deb" ]]; then
    echo $debfile
    echo Usage: $0 xxx.deb
    exit 1
fi

if [ ! -f $debpath ]; then
    echo $debpath not exist
    exit 1
fi

buildroot=$root/$debname
layout=$buildroot/layout
debian=$buildroot/layout/DEBIAN
mkdir -p $debian
dpkg -x $debpath $layout/
dpkg -e $debpath $debian/
chmod -R +rwx $debian
