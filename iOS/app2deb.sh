#!/bin/bash

# 该模块用于在iOS上将AppStore的App转换为越狱App的deb包

if [[ x$1 == x ]]; then
    echo Usage: $0 [apppath]
    exit 0
fi

if [[ ! $1 =~ .*.app$ ]]; then
    echo bundlepath must be .../xxxxx.app
    exit 0
fi

apppath=$1
spliter=(${apppath//// })
appbase=${spliter[${#spliter[*]}-1]}
appname=${appbase//.app/}

echo Appname is $appname

rm -rf /tmp/$appname
mkdir -p /tmp/$appname/{DEBIAN,Applications}
cp -rfp $apppath /tmp/$appname/Applications/

olddir=$PWD
cat >> /tmp/$appname/DEBIAN/control << EOF
Package: $appname
Name: $appname
Version: 1.0
Architecture: all
Description: $appname
Maintainer: $appname
Author: $appname
Section: $appname
EOF
cat >> /tmp/$appname/DEBIAN/extrainst_ << EOF
uicache
exit 0
EOF
dpkg -b /tmp/$appname $appname.deb
# rm -rf /tmp/$appname

echo DEB package create at $olddir/$appname.deb
