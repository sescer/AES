import os
import string
import random
from utils import random_iv_generator, add_PKCS5_padding, xor_hex_blocks, \
    unpad


def open_and_read_from_file(filename):
    with open(filename, "rb") as f:
        hex_array = []
        for offset in range(0, os.path.getsize(filename), 16):
            hex_array.append(bytes.hex(f.read(16)))
            f.seek(offset + 16)
        f.close()
    return hex_array


def write_in_file(filename, block_array):
    with open(filename, "ab") as f:
        for i in range(len(block_array)):
            f.write(bytes.fromhex(block_array[i]))
        f.close()


def create_file_with_random_letters(filename, size):
    chars = ''.join([random.choice(string.ascii_letters) for i in range(size)])
    with open(filename, 'w') as f:
        f.write(chars)


# https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
class CBC:
    def __init__(self, aes_algorithm, iv_length):
        self.aes_algorithm = aes_algorithm
        self.iv = random_iv_generator(iv_length)

    def encrypt(self, filename, encrypted_file_name):
        hex_array = open_and_read_from_file(filename)

        if len(hex_array[-1]) < 32:
            hex_array[-1] = add_PKCS5_padding(hex_array[-1], 16)

        cipher_array = [self.iv]

        iv = self.iv
        for i in range(len(hex_array)):
            block_to_cipher = xor_hex_blocks(iv, hex_array[i])
            cipher_array.append(self.aes_algorithm.cipher(block_to_cipher))

            iv = cipher_array[i + 1]
        write_in_file(encrypted_file_name, cipher_array)

    def decrypt(self, filename, decrypted_file_name):
        hex_array = open_and_read_from_file(filename)
        iv = hex_array[0]
        decrypted_array = []
        for i in range(1, len(hex_array)):
            decrypted_array.append(self.aes_algorithm.inv_cipher(hex_array[i]))
            decrypted_array[i - 1] = xor_hex_blocks(iv, decrypted_array[i - 1])
            iv = hex_array[i]

        decrypted_array[-1] = unpad(decrypted_array[-1])

        write_in_file(decrypted_file_name, decrypted_array)
