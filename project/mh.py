# Please use python3
import os
import math

def __egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def get_osrandom(f, t):
    rand = ord(os.urandom(1))
    return math.floor((rand / 256) * (t - f + 1) + f)

def get_superincreasing_list(length):
    if length == 0:
        return []
    list = []
    last_elem = get_osrandom(1, 10)
    list.append(last_elem)
    while len(list) < length:
        temp_elem = get_osrandom(sum(list) + 1, 3 * last_elem)
        list.append(temp_elem)
        last_elem = temp_elem
    return list

def is_coprime(a, b):
    g, _, _ = __egcd(a, b)
    return g == 1

def bit_arr(decimal, min_length):
    if decimal < 0:
        raise Exception('negative number is not supported.')
    list = []
    quotient = decimal // 2
    remainder = decimal % 2
    list.append(remainder)
    while quotient != 0:
        remainder = quotient % 2
        list.append(remainder)
        quotient = quotient // 2
    # pad the list
    while len(list) < min_length:
        list.append(0)
    list.reverse()
    return list

# mod inverse
def mod_inv(a, m):
    g, x, y = __egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


class MarkelHellmanKnapsackDecryptor:
    def __init__(self):
        # generate private key set
        self.w = get_superincreasing_list(8)
        list_sum = sum(self.w)
        # print("sum", list_sum)
        self.q = get_osrandom(list_sum + 1, 2 * list_sum)
        r = get_osrandom(1, self.q - 1)
        while not is_coprime(self.q, r):
            r = get_osrandom(1, self.q - 1)
        self.r = r
        # print("private key set:", self.w, self.q, self.r)

    def get_publickey(self):
        # generate public key
        public_key = [(x * self.r) % self.q for x in self.w]
        # print("public key", public_key)
        return MarkelHellmanKnapsackEncryptor(public_key)
        
    def decrypt(self, cipher):
        r_inv = mod_inv(self.r, self.q)
        # print("r inv:", r_inv)
        mod_cipher = (cipher * r_inv) % self.q
        # print("mod cipher:", mod_cipher)
        inv_bit_list = []
        for elem in self.w[::-1]:
            if elem <= mod_cipher:
                inv_bit_list.append(1)
                mod_cipher -= elem
            else:
                inv_bit_list.append(0)
        # print("decrypted bit list", inv_bit_list[::-1])
        char_ascii = 0
        for idx, bit in enumerate(inv_bit_list):
            char_ascii += bit * (2 ** idx)
        if char_ascii > 255:
            raise Exception('decryption error: resulting byte ascii > 255.')
        return chr(char_ascii)

    @staticmethod
    def generate():
        return MarkelHellmanKnapsackDecryptor()

class MarkelHellmanKnapsackEncryptor:
    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, byte):
        bin_rep = bit_arr(ord(byte), 8)
        # print("bit list:", bin_rep)
        return sum([a*b for a, b in zip(bin_rep, self.public_key)])

if __name__ == '__main__':
    message = "hello world!"
    print('message to be encrypted:', message)
    decrypted_message = ""
    for byte in message:
        key = MarkelHellmanKnapsackDecryptor.generate()
        # print('byte to be encrypted:', byte)
        cipher = key.get_publickey().encrypt(byte)
        # print("cipher:", cipher)
        byte = key.decrypt(cipher)
        # print("decoded cipher:", byte)
        decrypted_message += byte
    # print('===============================')
    print('decrypted message:', decrypted_message)

