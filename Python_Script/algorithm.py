import hashlib
import hmac
import math
import struct
import time
from random import randint

class mymd5:
    def __init__(self, msg, H=None, K=None, S=None):
        self.S = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]
        self.K = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ];
        self.H = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        ]
        self.msg = msg
        self.data = None
        if H is not None:
            self.H = H
        if K is not None:
            self.K = K
        if S is not None:
            self.S = S
        self.calc()
        
    def calc(self):
        msg = self.msg
        h0 = self.H[0]
        h1 = self.H[1]
        h2 = self.H[2]
        h3 = self.H[3]
        K = self.K
        S = self.S
        pad = lambda a: a + b'\0' * ((64 - ((len(a) + 8) % 64)) % 64)
        to_bytes = lambda v: struct.pack('<I', v)
        to_int32 = lambda b: struct.unpack('<I', b)[0]
        left_rot = lambda x,c: (((x & 0xffffffff) << c) | ((x & 0xffffffff) >> (32 - c))) & 0xffffffff
        byte_msg = pad(msg + b'\x80') + to_bytes(len(msg) * 8) + to_bytes(0)
        new_len = len(byte_msg) - 8
        
        for i in range(0, new_len, 64):
            m = [to_int32(byte_msg[i + j:i + j + 4]) for j in range(0, 64, 4)]
            a = h0
            b = h1
            c = h2
            d = h3
            for j in range(64):
                f = 0
                g = 0
                if j < 16:
                    f = ((b & c) | ((~b) & d)) & 0xffffffff
                    g = j
                elif j < 32:
                    f = ((d & b) | ((~d) & c)) & 0xffffffff
                    g = (5 * j + 1) % 16
                elif j < 48:
                    f = (b ^ c ^ d) & 0xffffffff
                    g = (3 * j + 5) % 16
                else:
                    f = (c ^ (b | (~d))) & 0xffffffff
                    g = (7 * j) % 16
                temp = d
                d = c
                c = b
                b = (b + left_rot((a + f + K[j] + m[g]), S[j])) & 0xffffffff
                a = temp
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
        self.data = to_bytes(h0) + to_bytes(h1) + to_bytes(h2) + to_bytes(h3)

    def hexdigest(self):
        return self.data.hex()

def test():
  md5_1 = mymd5(rs.encode()).hexdigest()
  print(md5_1)
  # 自定义md5执行速度:1ms/个   hashlib.md5执行速度:3.6us/个
