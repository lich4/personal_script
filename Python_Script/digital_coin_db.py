# -*- coding: utf-8 -*-

import urllib2
import sqlite3
import json
import time
from lxml import etree
import os

DEBUG = True

class HistoryUpdater(object):
    def __init__(self):
        if DEBUG:
            proxy_handler = urllib2.ProxyHandler({
                'http':'http://127.0.0.1:8888',
                'https':'http://127.0.0.1:8888',
            })
        urllib2.install_opener(urllib2.build_opener(proxy_handler))
        self.tblcaches = list()

    def UpdateOnePrice(self, coinname, coinid, site):
        '''
        更新单个表
        :param coinname: btc eth ...
        :param coinid: 123 456 ...
        :param site: conbase.com ....
        :return:
        '''
        block = 3600 # 1day
        baseurl = 'http://bitkan.com'
        tbl = site.replace('.', '') + '_' + coinname
        cx = sqlite3.connect('digitalcash.db')
        cu = cx.cursor()

        # 防止重复添加
        if tbl in self.tblcaches:
            return
        self.tblcaches.append(tbl)

        # 不存在则创建表
        try:
            sql = 'create table %s (t int primary key, c float, h float, l float, o float, v float)' % tbl
            cu.execute(sql)
        except Exception as e:
            pass # Already exist

        begintime = 1300000000

        # 获取数据库最后一项
        try:
            sql = 'select max(t) from %s' % tbl
            cu.execute(sql)
            out = cu.fetchone()[0]
            if out is not None:
                begintime = int(cu.fetchone()[0])
        except Exception as e:
            pass #

        # 在线获取最小值
        try:
            urlext = '/chart/%s/history?symbol=%s&resolution=1&from=0' % (coinid, site)
            response = urllib2.urlopen(baseurl + urlext).read()
            if response.find('Error') != -1:
                return # 服务器异常
            di = json.loads(response)
            if len(di['t']) == 0:
                return # 空数据
            if begintime < int(di['t'][0]):
                begintime = int(di['t'][0])
        except Exception as e:
            print urlext, e.message

        errtime = 0
        begintime += 60
        endtime = int(time.time())
        while begintime < endtime:
            endtime = int(time.time())
            urlext = '/chart/%s/history?symbol=%s&resolution=1&from=%d&to=%d' % \
                     (coinid, site, begintime, begintime + block)
            try:
                response = urllib2.urlopen(baseurl + urlext).read()
                di = json.loads(response)
                length = len(di['t'])
                for j in range(0, length):
                    cx.execute('insert or ignore into %s values (?,?,?,?,?,?)' % tbl,
                               (int(di['t'][j]),  float(di['c'][j]), float(di['h'][j]), float(di['l'][j]),
                                float(di['o'][j]), float(di['v'][j])))
                # print '%s-%s done' % (time.ctime(int(di['t'][0])), time.ctime(int(di['t'][-1])))
                begintime += block
                if begintime < int(di['t'][-1]):
                    begintime = int(di['t'][-1]) + block
            except Exception as e:
                print e.message
                errtime += 1
                begintime += block
            if errtime > 3:
                return
            cx.commit()
        cu.close()
        cx.close()
        print '%s updated' % tbl

    def UpdateAll(self):
        '''
        Download configuration from bitkan
        :return:
        '''
        baseurl = 'http://bitkan.com/price'
        cointypenodes = list()
        try:
            tree = etree.HTML(urllib2.urlopen(baseurl).read())
        except Exception as e:
            print 'error 1'
        nodes = tree.xpath("//ul[@class='nav nav-tabs']//a")
        for node in nodes:
            if node.attrib['href'].find('?category') != -1:
                cointypenodes.append(node)
        for item in cointypenodes:
            coinname = item.text.replace('?category=', '',).replace('#categories', '')
            subtree = etree.HTML(urllib2.urlopen(baseurl + item.attrib['href']).read())
            subnodes = subtree.xpath("//div[@class='col-md-6']//a")
            for node in subnodes:
                if node.attrib['href'].find('/chart') != -1 and len(node.getchildren()) > 0:
                    spannode = node.getchildren()[0]
                    if spannode.attrib['class'].find('sprite-') != -1:
                        if spannode.attrib['class'].find('eth') != -1:
                            break # 未知数据
                        coinid = node.attrib['href'].replace('/chart/', '')
                        site = spannode.attrib['class'].replace('sprite sprite-', '')
                        self.UpdateOnePrice(coinname, coinid, site)

if __name__ == '__main__':
    HistoryUpdater().UpdateAll()
