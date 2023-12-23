#!/bin/bash

# 该模块在iOS上将App所在Bundle目录打包为IPA文件

if [[ x$1 == x ]]; then
    echo Usage: $0 [apppath]
    exit 0
fi

if [ ! -f /usr/bin/zip ]; then
    apt install zip
fi

apppath=$(echo /private/var/containers/Bundle/Application/*/$1.app)

if [ ! -d $apppath ]; then
    apppath=$(echo /private/var/mobile/Containers/Bundle/Application/*/$1.app)
    if [ ! -d $apppath ]; then
        echo app not found
        exit
    fi
fi

spliter=(${apppath//// })
appbase=${spliter[${#spliter[*]}-1]}
appname=${appbase//.app/}

echo Appname is $appname

rm -rf /tmp/$appname
mkdir -p /tmp/$appname/Payload
cp -rfp $apppath /tmp/$appname/Payload/
if [ -f $apppath/../iTunesArtwork ]; then
    cp -fp $apppath/../iTunesArtwork /tmp/$appname/iTunesArtwork
fi
if [ -f $apppath/../iTunesMetadata.plist ]; then
    cp -fp $apppath/../iTunesMetadata.plist /tmp/$appname/iTunesMetadata.plist
fi
if [ -f $apppath/../BundleMetadata.plist ]; then
    cp -fp $apppath/../BundleMetadata.plist /tmp/$appname/BundleMetadata.plist
fi
if [ -f $apppath/Icon.png ]; then
    cp -fp $apppath/Icon.png /tmp/$appname/iTunesArtwork
fi
if [ -f $apppath/Default.png ]; then
    cp -fp $apppath/Default.png /tmp/$appname/iTunesArtwork
fi
olddir=$PWD
cd /tmp/$appname
zip -r $olddir/$appname.ipa Payload
cd $olddir
rm -rf /tmp/$appname

echo IPA package create at $olddir/$appname.ipa
