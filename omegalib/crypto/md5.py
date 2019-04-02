# coding: utf-8

import struct

class MD5(object):
    def __init__(self):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        self.md5sum = None
        self.msg = b''
        self.prev_len = 0
        self.done_update = False

    def get_init_vector(self):
        return (self.A, self.B, self.C, self.D)

    def set_init_vector(self, init_vec):
        self.A, self.B, self.C, self.D = init_vec

    def update(self, msg):
        self.msg += msg
        self.done_update = False


    def padding(self, msg):
        p_len = 64 - ((len(msg) + 8) % 64)
        msg_len = (8 * (self.prev_len + len(msg))) % 18446744073709551616 # 18446744073709551616 = 2**64
        if p_len < 64:
            msg += b'\x80' + b'\x00' * (p_len - 1)
        msg += struct.pack('<Q', msg_len)
        return msg

    def digest(self):
        if not self.done_update:
            A, B, C, D  = self.__calc__()
            self.md5sum = struct.pack('<IIII', A, B, C, D)
            self.update = True
        return self.md5sum

    def hexdigest(self):
        return self.digest().hex()

    def __calc__(self):
        #append padding to msg
        msg = self.padding(self.msg)
        # define calc functions

        NOT = lambda x: x ^ 0xffffffff
        F = lambda x,y,z: (x & y) | (NOT(x) & z)
        G = lambda x,y,z: (x & z) | (y & NOT(z))
        H = lambda x,y,z: x ^ y ^ z
        I = lambda x,y,z: y ^ (x | NOT(z))

        RL = lambda x,n: (x << n) | (x >> (32 - n))
        OPERATION = lambda func,a,b,c,d,k,s,i: (b + (RL((a + func(b,c,d) + X[k] + T[i-1]) & 0xffffffff, s) & 0xffffffff)) & 0xffffffff

        T = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ]


        A, B, C, D = self.get_init_vector()
        for i in range(len(msg) // 64):
            M = msg[i*64:i*64 + 64]
            X = []
            for j in range(16):
                X.append(struct.unpack('<I', M[j*4:j*4+4])[0])
            AA, BB, CC, DD = A, B, C, D
            A = OPERATION(F, A, B, C, D, 0, 7, 1)
            D = OPERATION(F, D, A, B, C, 1, 12, 2)
            C = OPERATION(F, C, D, A, B, 2, 17, 3)
            B = OPERATION(F, B, C, D, A, 3, 22, 4)
            A = OPERATION(F, A, B, C, D, 4, 7, 5)
            D = OPERATION(F, D, A, B, C, 5, 12, 6)
            C = OPERATION(F, C, D, A, B, 6, 17, 7)
            B = OPERATION(F, B, C, D, A, 7, 22, 8)
            A = OPERATION(F, A, B, C, D, 8, 7, 9)
            D = OPERATION(F, D, A, B, C, 9, 12, 10)
            C = OPERATION(F, C, D, A, B, 10, 17, 11)
            B = OPERATION(F, B, C, D, A, 11, 22, 12)
            A = OPERATION(F, A, B, C, D, 12, 7, 13)
            D = OPERATION(F, D, A, B, C, 13, 12, 14)
            C = OPERATION(F, C, D, A, B, 14, 17, 15)
            B = OPERATION(F, B, C, D, A, 15, 22, 16)

            A = OPERATION(G, A, B, C, D, 1, 5, 17)
            D = OPERATION(G, D, A, B, C, 6, 9, 18)
            C = OPERATION(G, C, D, A, B, 11, 14, 19)
            B = OPERATION(G, B, C, D, A, 0, 20, 20)
            A = OPERATION(G, A, B, C, D, 5, 5, 21)
            D = OPERATION(G, D, A, B, C, 10, 9, 22)
            C = OPERATION(G, C, D, A, B, 15, 14, 23)
            B = OPERATION(G, B, C, D, A, 4, 20, 24)
            A = OPERATION(G, A, B, C, D, 9, 5, 25)
            D = OPERATION(G, D, A, B, C, 14, 9, 26)
            C = OPERATION(G, C, D, A, B, 3, 14, 27)
            B = OPERATION(G, B, C, D, A, 8, 20, 28)
            A = OPERATION(G, A, B, C, D, 13, 5, 29)
            D = OPERATION(G, D, A, B, C, 2, 9, 30)
            C = OPERATION(G, C, D, A, B, 7, 14, 31)
            B = OPERATION(G, B, C, D, A, 12, 20, 32)

            A = OPERATION(H, A, B, C, D, 5, 4, 33)
            D = OPERATION(H, D, A, B, C, 8, 11, 34)
            C = OPERATION(H, C, D, A, B, 11, 16, 35)
            B = OPERATION(H, B, C, D, A, 14, 23, 36)
            A = OPERATION(H, A, B, C, D, 1, 4, 37)
            D = OPERATION(H, D, A, B, C, 4, 11, 38)
            C = OPERATION(H, C, D, A, B, 7, 16, 39)
            B = OPERATION(H, B, C, D, A, 10, 23, 40)
            A = OPERATION(H, A, B, C, D, 13, 4, 41)
            D = OPERATION(H, D, A, B, C, 0, 11, 42)
            C = OPERATION(H, C, D, A, B, 3, 16, 43)
            B = OPERATION(H, B, C, D, A, 6, 23, 44)
            A = OPERATION(H, A, B, C, D, 9, 4, 45)
            D = OPERATION(H, D, A, B, C, 12, 11, 46)
            C = OPERATION(H, C, D, A, B, 15, 16, 47)
            B = OPERATION(H, B, C, D, A, 2, 23, 48)


            A = OPERATION(I, A, B, C, D, 0, 6, 49)
            D = OPERATION(I, D, A, B, C, 7, 10, 50)
            C = OPERATION(I, C, D, A, B, 14, 15, 51)
            B = OPERATION(I, B, C, D, A, 5, 21, 52)
            A = OPERATION(I, A, B, C, D, 12, 6, 53)
            D = OPERATION(I, D, A, B, C, 3, 10, 54)
            C = OPERATION(I, C, D, A, B, 10, 15, 55)
            B = OPERATION(I, B, C, D, A, 1, 21, 56)
            A = OPERATION(I, A, B, C, D, 8, 6, 57)
            D = OPERATION(I, D, A, B, C, 15, 10, 58)
            C = OPERATION(I, C, D, A, B, 6, 15, 59)
            B = OPERATION(I, B, C, D, A, 13, 21, 60)
            A = OPERATION(I, A, B, C, D, 4, 6, 61)
            D = OPERATION(I, D, A, B, C, 11, 10, 62)
            C = OPERATION(I, C, D, A, B, 2, 15, 63)
            B = OPERATION(I, B, C, D, A, 9, 21, 64)


            A = (A + AA) % 4294967296
            B = (B + BB) % 4294967296
            C = (C + CC) % 4294967296
            D = (D + DD) % 4294967296

        return A, B, C, D


if __name__ == "__main__":
    md5 = MD5()
    md5.update("Hello".encode())
    print(md5.hexdigest())









