# -*- coding: utf-8 -*-

"""
Usage:
    # iptables allow all connection
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --sport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

    python testcon.py --local_port=80 # As server
    python testcon.py --remote_addr=61.135.169.125 --remote_port=80 # As client
"""

import os
import socket
import sys
import time

buffer_size = 1024


def do_send(s, sendfunc, address_tuple, data):
    """
        do send
    """
    try:
        if sendfunc == 'send':
            return s.send(data)
        elif sendfunc == 'sendto':
            return s.sendto(data, address_tuple)
        elif sendfunc == 'write':
            return os.write(s.fileno(), data)
    except:
        pass


def do_recv(s, recvfunc):
    """
        do recv
    """
    try:
        if recvfunc == 'recv':
            return s.recv(buffer_size), None
        elif recvfunc == 'recvfrom':
            return s.recvfrom(buffer_size)
        elif recvfunc == 'read':
            return os.read(s.fileno(), buffer_size), None
    except:
        pass


def start_sock_stub(params):
    """
        启动普通socket Server or Client
    """
    family = socket.AF_INET
    if params['family'] == 'inet4':
        family = socket.AF_INET
    elif params['family'] == 'unix':
        family = socket.AF_UNIX
    if 'bind' in params:  # Server
        if 'data' not in params:
            params['data'] = 'Server receive a message'
        if params['type'] == 'tcp':
            s = socket.socket(family, socket.SOCK_STREAM)
        elif params['type'] == 'udp':
            s = socket.socket(family, socket.SOCK_DGRAM)
        else:
            return
        s.bind(params['bind'])
        if params['type'] == 'tcp':
            s.listen(1)
        while params['testnum'] > 0:
            ca = None
            if params['type'] == 'tcp':
                cs, ca = s.accept()
                if not params['silent']:
                    print('accept:', ca)
            elif params['type'] == 'udp':
                cs = s
            if params['order'] == 'recv_send':
                data, ca_x = do_recv(cs, params['recvfunc'])
                if ca is None and ca_x is not None:
                    ca = ca_x
                if not params['silent']:
                    print('recv ' + params['type'] + ': ' + data, '' if ca is None else ca)
                do_send(cs, params['sendfunc'], ca, params['data'])
            elif params['order'] == 'send_recv':
                if ca is None and 'connect' in params:
                    ca = params['connect']
                if ca is None and 'sendto' in params:
                    ca = params['sendto']
                do_send(cs, params['sendfunc'], ca, params['data'])
                data, ca = do_recv(cs, params['recvfunc'])
                if not params['silent']:
                    print('recv ' + params['type'] + ': ' + data, '' if ca is None else ca)
            if params['type'] == 'tcp':
                cs.close()
            params['testnum'] = params['testnum'] - 1
        s.close()
    else:  # Client
        if 'data' not in params:
            params['data'] = 'Client send a message'
        tb = time.time()
        for i in range(0, params['testnum']):
            if params['type'] == 'tcp':
                s = socket.socket(family, socket.SOCK_STREAM)
            elif params['type'] == 'udp':
                s = socket.socket(family, socket.SOCK_DGRAM)
            else:
                return
            if 'connect' in params:
                s.connect(params['connect'])
            if params['order'] == 'send_recv':
                if 'connect' in params:
                    do_send(s, params['sendfunc'], params['connect'], params['data'])
                elif 'sendto' in params:
                    do_send(s, params['sendfunc'], params['sendto'], params['data'])
                data, ca = do_recv(s, params['recvfunc'])
                if not params['silent']:
                    print('recv ' + params['type'] + ': ' + data, '' if ca is None else ca)
            elif params['order'] == 'recv_send':
                data, ca = do_recv(s, params['recvfunc'])
                if not params['silent']:
                    print('recv ' + params['type'] + ': ' + data, '' if ca is None else ca)
                if 'connect' in params:
                    s.connect(params['connect'])
                    do_send(s, params['sendfunc'], params['connect'], params['data'])
                elif 'sendto' in params:
                    do_send(s, params['sendfunc'], params['sendto'], params['data'])
            s.close()
        te = time.time()
        print('time elapse:', (te - tb))


def start_npipe_stub(params):
    """
        启动named pipe Server or Client
    """
    if 'mkfifo' in params: # server
        if 'data' not in params:
            params['data'] = 'Server receive a message'
        path = params['mkfifo']
        np_patha = path + '.a'
        np_pathb = path + '.b'
        os.unlink(np_patha)
        os.unlink(np_pathb)
        os.mkfifo(np_patha, 0660)
        os.mkfifo(np_pathb, 0660)
        fifoa = os.open(np_patha, os.O_RDONLY)
        while params['testnum'] > 0:
            fifob = os.open(np_pathb, os.O_WRONLY)
            if params['order'] == 'recv_send':
                data = os.read(fifoa, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
                os.write(fifob, params['data'])
            elif params['order'] == 'send_recv':
                os.write(fifob, params['data'])
                data = os.read(fifoa, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
            os.close(fifob)
            params['testnum'] -= 1
        os.close(fifoa)
    elif 'open' in params: # client
        if 'data' not in params:
            params['data'] = 'Client send a message'
        path = params['open']
        np_patha = path + '.a'
        np_pathb = path + '.b'
        while params['testnum'] > 0:
            fifoa = os.open(np_patha, os.O_WRONLY)
            fifob = os.open(np_pathb, os.O_RDONLY)
            if params['order'] == 'recv_send':
                data = os.read(fifob, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
                os.write(fifoa, params['data'])
            elif params['order'] == 'send_recv':
                os.write(fifoa, params['data'])
                data = os.read(fifob, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
            os.close(fifob)
            os.close(fifoa)
            params['testnum'] -= 1

        fd = os.open(path, os.O_RDWR)
        while params['testnum'] > 0:
            if params['order'] == 'recv_send':
                data = os.read(fd, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
                os.write(fd, 'Server receive a message')
            elif params['order'] == 'send_recv':
                os.write(fd, 'Server send a message')
                data = os.read(fd, buffer_size)
                if not params['silent']:
                    print('read ' + params['type'] + ': ' + data)
            params['testnum'] -= 1


def print_usage():
    """
        print usage
    """
    print("Usage:")  # bind一端作为server端
    print("\t--type=tcp/udp/pipe")
    print("\t--family=inet4/unix")
    print("\t--bind=port")
    print("\t--connect=address:port")
    print("\t--sendto=address:port")
    print("\t--sendfunc=send/sendto/write")
    print("\t--recvfunc=recv/recvfrom/read")
    print("\t--order=send_recv/recv_send")
    print("\t--silent")
    print("\t--testnum=123")
    print("\t--data=test")
    print("NamedPipe Model:")
    print("\tServer: --type=pipe --mkfifo=/path/to/pipe")
    print("\tClient: --type=pipe --open=/path/to/pipe")
    print("TCP Model:")
    print("\tServer: --type=tcp --bind=:111")
    print("\tClient: --type=tcp --connect=127.0.0.1:111")
    print("\tServer: --type=tcp --family=unix --bind=/path/to/sock")
    print("\tClient: --type=tcp --family=unix --connect=/path/to/sock")
    print("UDP Model I:")
    print("\tServer: --type=udp --bind=:111")
    print("\tClient: --type=udp --sendto=127.0.0.1:111")
    print("UDP Model II:")
    print("\tServer: --type=udp --bind=:111")
    print("\tClient: --type=udp --connect=127.0.0.1:111")
    print("UDP Model III:")
    print("\tPeer: --type=udp --bind=:111 --connect=127.0.0.1:112 --order=recv_send")
    print("\tPeer: --type=udp --bind=:112 --connect=127.0.0.1:111 --order=send_recv")
    print("UDP Model IV:")
    print("\tPeer: --type=udp --bind=:111 --sendto=127.0.0.1:112 --order=recv_send")
    print("\tPeer: --type=udp --bind=:112 --sendto=127.0.0.1:111 --order=send_recv")


if __name__ == '__main__':
    params = {
        'type': 'tcp',
        'silent': False,
        'testnum': 1,
        'family': 'inet4'
    }
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(0)
    for arg in sys.argv[1:]:
        arg = arg.replace('--', '')
        if arg.count('=') == 0:
            params[arg] = True
        else:
            k, v = tuple(arg.split('='))
            if k in ['family', 'type', 'sendfunc', 'recvfunc', 'order', 'mkfifo', 'open', 'data']:
                params[k] = v
            elif k in ['testnum']:
                params[k] = int(v)
            elif k in ['bind', 'connect', 'sendto']:
                if params['family'] == 'inet4':
                    params[k] = v.split(':')[0], int(v.split(':')[1])
                    if params[k][0] == '':
                        params[k] = '0.0.0.0', int(v.split(':')[1])
                elif params['family'] == 'unix':
                    params[k] = v
    if 'order' not in params:
        if 'bind' in params:
            params['order'] = 'recv_send'
        else:
            params['order'] = 'send_recv'
    if params['type'] == 'tcp':
        if 'sendfunc' not in params:
            params['sendfunc'] = 'send'
        if 'recvfunc' not in params:
            params['recvfunc'] = 'recv'
        start_sock_stub(params)
    elif params['type'] == 'udp':
        if 'sendfunc' not in params:
            params['sendfunc'] = 'sendto'
        if 'recvfunc' not in params:
            params['recvfunc'] = 'recvfrom'
        start_sock_stub(params)
    elif params['type'] == 'pipe':
        start_npipe_stub(params)
