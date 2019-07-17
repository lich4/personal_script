#! /usr/bin/env python
# # -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
from lxml import etree
import random
import re
import socket
import ssl
import sys
import threadpool
import time

defencode = 'utf-8'
ssl._create_default_https_context = ssl._create_unverified_context

if sys.version_info[0] == 2:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    import urllib2 as urllib_
elif sys.version_info[0] == 3:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import urllib.request as urllib_


logging.basicConfig(level=logging.INFO, filename='serv.log', filemode='a',
    format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s')


def FLog(msg):
    logging.info(msg)
    print(datetime.datetime.now().strftime('%c') + '\t' + msg)


def RequestWithProxy(url, proxy, headers, postdata, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    try:
        opener = urllib_.build_opener(urllib_.ProxyHandler({
            "http": proxy,
            "https": proxy,
        }))
        content = opener.open(urllib_.Request(url, headers=headers, data=postdata), timeout=timeout).read()
        return content.decode('UTF-8').encode(defencode)
    except Exception as e:
        print(e)
        return None


def RequestWithDefProxy(url, headers, postdata, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    return RequestWithProxy(url, '192.168.1.8:8888', headers, postdata, timeout)
    try:
        opener = urllib_.build_opener()
        content = opener.open(urllib_.Request(url, headers=headers, data=postdata), timeout=timeout).read()
        return content.decode('UTF-8').encode(defencode)
    except Exception as e:
        print(e)
        return None


def md5(s):
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest()


def randidfv():
    # generate IDFV
    c_i = '0123456789ABCDEF'
    idfv = "".join([c_i[random.randint(0, 15)] for i in range(32)])
    idfv = idfv[0:8] + "-" + idfv[8:12] + "-" + idfv[12:16] + "-" + idfv[16:20] + "-" + idfv[20:]
    return idfv


def JianshuPublish(username, password, title, content):
    xauth1pre = '2900143726e290a4d84a3bc8c7288e7e'
    xauth2pre = '99a017cea4bfa4cb'
    data = dict()
    ts = '%d' % int(time.time())
    headers = {
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Hugo',
        'X-App-Name': 'hugo',
        'X-Auth-1': md5(xauth1pre + ts),
        'X-App-Version': '5.12.0',
        'X-Device-Guid': randidfv(),
        'X-Timestamp': ts,
    }
    params = {
        'sign_in_name': username,
        'password': password,
    }
    postdata = '&'.join(['%s=%s' % (i, params[i]) for i in params])
    res = RequestWithDefProxy('https://s0.jianshuapi.com/v2/users/sign_in', headers=headers, postdata=postdata)
    if res is None:
        FLog('JianshuPublish login response error')
        return False
    try:
        data.update(json.loads(res))
    except Exception as e:
        FLog('JianshuPublish login json decode error')
        return False
    if 'id' not in data:
        FLog('JianshuPublish login json data error')
        return False
    FLog('JianshuPublish login success')

    headers = {
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Hugo',
        'X-App-Name': 'hugo',
        'X-Auth-1': md5(xauth1pre + ts),
        'X-Auth-2': md5(xauth2pre + ts),
        'X-App-Version': '5.12.0',
        'X-Device-Guid': randidfv(),
        'X-NETWORK': '1',
        'X-Timestamp': ts,
        'X-User-Id': data['id'],
    }
    params = {
        'title': ''.join(['%%%02X' % ord(i) for i in title]),
        'content': ''.join(['%%%02X' % ord(i) for i in content]),
        'note_type': 'markdown',
    }
    postdata = '&'.join(['%s=%s' % (i, params[i]) for i in params])
    res = RequestWithDefProxy('https://s0.jianshuapi.com/v2/author/notes', headers=headers, postdata=postdata)
    if res is None:
        FLog('JianshuPublish postnote response error')
        return False
    try:
        data.update(json.loads(res))
    except Exception as e:
        FLog('JianshuPublish postnote json decode error')
        return False
    if 'note' not in data:
        FLog('JianshuPublish postnote data error')
        return False
    FLog('JianshuPublish postnote success')

    headers = {
        'Accept': '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Hugo',
        'X-App-Name': 'hugo',
        'X-Auth-1': md5(xauth1pre + ts),
        'X-Auth-2': md5(xauth2pre + ts),
        'X-App-Version': '5.12.0',
        'X-Device-Guid': randidfv(),
        'X-NETWORK': '1',
        'X-Timestamp': ts,
        'X-User-Id': data['id'],
    }
    params = {
    }
    postdata = '&'.join(['%s=%s' % (i, params[i]) for i in params])
    res = RequestWithDefProxy('https://s0.jianshuapi.com/v2/author/notes/%d/publicize' % data['note']['id'],
                              headers=headers, postdata=postdata)
    if res is None:
        FLog('JianshuPublish publicize response error')
        return False
    try:
        data.update(json.loads(res))
    except Exception as e:
        FLog('JianshuPublish publicize json decode error')
        return False
    if 'note' not in data:
        FLog('JianshuPublish publicize data error')
        return False
    FLog('JianshuPublish publicize success')
    return True


if __name__ == '__main__':
    JianshuPublish('手机号', '密码', '测试md', 'test md content')

