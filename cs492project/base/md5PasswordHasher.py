import math
import bitarray
from bitarray.util import int2ba
from django.contrib.auth.hashers import BasePasswordHasher


class md5PasswordHasher(BasePasswordHasher):
    algorithm = "md5"

    def encode(self, password, salt=None):
        data = bitarray.bitarray()
        data.frombytes(password.encode('utf-8'))

        print("Beginning Md5 hash")
        print("Password: " + password)
        print()

        print("Data: ")
        print(data)
        print()

        data.append(1)
        while len(data) % 512 != 448:
            data.append(0)
        data_length = len(password) * 8
        data.extend(int2ba(data_length, length=64))
        print("Padded Data: ")
        print(data)
        print(len(data))
        print()

        num_blocks = len(data) // 512
        blocks = [data[i * 512:(i + 1) * 512] for i in range(num_blocks)]
        print("Blocks: ")
        print(data)
        print()

        T = [int(abs(math.sin(i + 1)) * pow(2, 32)) & 0xFFFFFFFF for i in range(64)]

        def F(x, y, z):
            return (x & y) | (~x & z)

        def G(x, y, z):
            return (x & z) | (y & ~z)

        def H(x, y, z):
            return x ^ y ^ z

        def I(x, y, z):
            return y ^ (x | ~z)

        for block in blocks:
            A = 0x67452301
            B = 0xefcdab89
            C = 0x98badcfe
            D = 0x10325476

            M = [int(block[i * 32:(i + 1) * 32].to01(), 2) for i in range(16)]
            print("Message segments: ")
            print(M)
            print()

            for i in range(64):
                if i < 16:
                    result = F(B, C, D)
                    k = i
                    shift_amount = [7, 12, 17, 22][i % 4]
                elif i < 32:
                    result = G(B, C, D)
                    k = (5 * i + 1) % 16
                    shift_amount = [5, 9, 14, 20][(i % 4)]
                elif i < 48:
                    result = H(B, C, D)
                    k = (3 * i + 5) % 16
                    shift_amount = [4, 11, 16, 23][(i % 4)]
                else:
                    result = I(B, C, D)
                    k = (7 * i) % 16
                    shift_amount = [6, 10, 15, 21][(i % 4)]

                result += (A + M[k] + T[i]) & 0xFFFFFFFF
                A, B, C, D = D, (A + ((result << shift_amount) | (result >> (32 - shift_amount))) + B) & 0xFFFFFFFF, B, C

                print("Round: " + str(i))
                print(A, B, C, D)
                print()

        hashed = '{:08x}{:08x}{:08x}{:08x}'.format(A, B, C, D)
        print(hashed)
        return md5PasswordHasher.algorithm + "$" + salt + "$" + hashed

    def verify(self, password, encoded):
        algorithm, salt, hash_str = encoded.split('$', 2)
        re_encoded = self.encode(password, salt)
        return encoded == re_encoded

    def safe_summary(self, encoded):
        return {'algorithm': self.algorithm, 'hash': encoded}
