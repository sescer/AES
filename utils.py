from constants import sbox, inv_sbox, mix_matrix, inv_mix_matrix


def look_up(byte, inverse=False):
    # 4 MSB
    x = byte >> 4
    # 4 LSB
    y = byte & 0x0F
    return sbox[x][y] if not inverse else inv_sbox[x][y]


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


def byte_list_to_word(byte_list):
    word = 0
    for byte in byte_list:
        word = (word << 8) + byte
    return word


def word_to_byte_list(word):
    byte_list = []
    for i in range(4):
        byte = word & 0xff
        byte_list.append(byte)
        word >>= 8
    byte_list.reverse()
    return byte_list


def xtime(a):
    # left shift by 1 and apply bitmask (8bits)
    b = a << 1 & 0xff
    # if leftmost bit is 1, then XOR with 0x1b
    if a >> 7 == 1:
        b ^= 0x1b
    return b


def transpose(lst):
    return [[row[i] for row in lst] for i in range(len(lst[0]))]


def to_matrix(state):
    state = [state[i:i+4] for i in range(0, len(state), 4)]
    state = transpose(state)
    return state


def to_list(state):
    state = transpose(state)
    state = sum(state, [])
    return state


def words_to_key(w, a, b):
    result = []
    for i in range(a, b + 1):
        temp = word_to_byte_list(w[i])
        result += temp
    return result
