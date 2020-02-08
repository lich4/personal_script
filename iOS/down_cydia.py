#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
说明：该模块自动下载cydia下的所有deb包
'''

import os
import sys
import ssl
import bz2
import gzip
import lzma

ssl._create_default_https_context = ssl._create_unverified_context

if sys.version_info[0] == 2:
    import urllib2 as urllib_
elif sys.version_info[0] == 3:
    import urllib.request as urllib_


def RequestWithDefProxy(url):
    try:
        headers = {
            'X-Machine': 'iPhone6,1',
            'X-Unique-ID': 'b596768cbbb2b54486c911832f2739b5d061c59f',
            'X-Firmware': '10.0',
            'User-Agent': 'Telesphoreo APT-HTTP/1.0.592',
            "Content-Length": 0
        }
        req = urllib_.Request(url, headers=headers)
        res = urllib_.urlopen(req)
        return res.read()
    except Exception as e:
        print(e)
        return None

def down_cydia(baseurl, basedir='.'):
    packages = list()
    if not baseurl.startswith('http'):
        baseurl = 'http://' + baseurl
    if baseurl.endswith('/'):
        baseurl = baseurl[:len(baseurl-1)]
    packages_data = RequestWithDefProxy(baseurl + '/./Packages')
    if packages_data is None:
        packages_data = RequestWithDefProxy(baseurl + '/./Packages.gz')
        print('try .gz')
        if packages_data is None:
            packages_data = RequestWithDefProxy(baseurl + '/./Packages.xz')
            print('try .xz')
            if packages_data is None:
                packages_data = RequestWithDefProxy(baseurl + '/./Packages.bz2')
                print('try .bz2')
                if packages_data is None:
                    print('Package parse failed')
                    return
                else:
                    packages_data = bz2.BZ2Decompressor().decompress(packages_data)
            else:
                packages_data = lzma.decompress(packages_data)
        else:
                packages_data = gzip.decompress(packages_data)
    packages_data = packages_data.decode('utf-8')
    for package_data in packages_data.split('\n\n'):
        package = dict()
        for package_item in package_data.split('\n'):
            i = package_item.find(':')
            if i < 0:
                continue
            k = package_item[:i].strip()
            v = package_item[i+1:].strip()
            package[k] = v
        if len(package) > 0:
            packages.append(package)
    i = 0
    for package in packages:
        if 'Name' not in package:
            package['Name'] = package['Package']
        filename = package['Name'] + '_' + package['Version'] + '.deb'
        package['__filename__'] = filename
        if package['Filename'].startswith('/'):
            fileurl = baseurl + package['Filename']
        else:
            fileurl = baseurl + '/' + package['Filename']
        package['__fileurl__'] = fileurl
        print('%d: %s' % (i, filename))
        i += 1
    print('all: all debs')
    sel = input('select index:')
    down_packages = list()
    if sel == 'all':
        down_packages = packages
    else:
        down_packages.append(packages[int(sel)])
    for package in down_packages:
        filename = package['__filename__']
        fileurl = package['__fileurl__']
        print('Downloading ' + fileurl)
        filedata = RequestWithDefProxy(fileurl)
        if filedata is None:
            print('Download file failed ' + fileurl)
            continue
        filepath = basedir + '/' + filename
        print('Download file success ' + filepath)
        with open(filepath, 'wb') as f:
            f.write(filedata)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python down_cydia.py cydia源')
        exit(0)
    url = sys.argv[1]
    down_cydia(url)

# python down_cydia.py http://apt.touchsprite.com packages
