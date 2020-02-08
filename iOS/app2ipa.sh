#!/bin/bash

# 该模块在iOS上将App所在Bundle目录打包为IPA文件

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
mkdir -p /tmp/$appname/Payload
cp -rfp $apppath /tmp/$appname/Payload/
if [ -f $apppath/../iTunesArtwork ]; then
    cp -fp $apppath/../iTunesArtwork /tmp/$appname/iTunesArtwork
elif [ -f $apppath/Icon.png ]; then
    cp -fp $apppath/Icon.png /tmp/$appname/iTunesArtwork
elif [ -f $apppath/Default.png ]; then
    cp -fp $apppath/Default.png /tmp/$appname/iTunesArtwork
fi
olddir=$PWD
cd /tmp/$appname
zip -r $olddir/$appname.ipa Payload
cd $olddir
rm -rf /tmp/$appname

echo IPA package create at $olddir/$appname.ipa
