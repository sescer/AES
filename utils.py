import os
from constants import mix_matrix, inv_mix_matrix


def random_key_generator(key_length):
    return bytes.hex(os.urandom(key_length // 8))


def random_iv_generator(iv_length):
    return bytes.hex(os.urandom(iv_length))


def text2matrix(text, len=16):
    state = []
    for i in range(len):
        byte = int(text[i * 2:i * 2 + 2], 16)
        if i % 4 == 0:
            state.append([byte])
        else:
            state[i // 4].append(byte)

    return state


def matrix2text(s, len=16):
    text = ""
    for i in range(len // 4):
        for j in range(4):
            text += format(s[i][j], '02x')

    return text


def ff_multiply(a, b):
    sum = 0
    for _ in range(8):
        if not a or not b:
            break
        if b & 0x01:
            sum ^= a
        b = b >> 1
        a = xtime(a)
    return sum


def mult_matrix(a0, a1, a2, a3, inverse):
    b = [0, 0, 0, 0]
    if inverse is False:
        for i in range(4):
            b[i] = ff_multiply(a0, mix_matrix[i][0]) ^ ff_multiply(a1, mix_matrix[i][1]) ^ ff_multiply(a2, mix_matrix[i][2]) ^ ff_multiply(a3, mix_matrix[i][3])
    else:
        for i in range(4):
            b[i] = ff_multiply(a0, inv_mix_matrix[i][0]) ^ ff_multiply(a1, inv_mix_matrix[i][1]) ^ ff_multiply(a2, inv_mix_matrix[i][2]) ^ ff_multiply(a3, inv_mix_matrix[i][3])
    return b


def xtime(b):
    if b & 0x80:
        b = b << 1
        b ^= 0x1B
    else:
        b = b << 1

    return b & 0xFF


def add_PKCS5_padding(block, block_length):
    bytes_to_pad = block_length - len(block) // 2
    for _ in range(bytes_to_pad):
        block += format(bytes_to_pad, '02x')
    return block


def unpad(block):
    bytes_to_unpad = int(block[-2:], 16)
    return block[:-bytes_to_unpad * 2]


def xor_hex_blocks(block_1, block_2):
    return format(int(block_1, 16) ^ int(block_2, 16), '032x')
