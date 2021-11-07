from constants import rcon, N_b
from utils import to_list, to_matrix, words_to_key, byte_list_to_word,\
    look_up, mult_matrix


def sub_bytes(state, inverse=False):
    """
    Transformation in the Cipher that processes the State using a non
    linear byte substitution table (S-box) that operates on each of the
    State bytes independently.

    :param state:Intermediate Cipher result that can be pictured as a rectangular array
    of bytes, having four rows and Nb columns.

    :param inverse: Flag for inverse function
    """
    for x in range(len(state)):
        for y in range(len(state[x])):
            state[x][y] = look_up(state[x][y], inverse)


def shift_rows(state, inverse=False):
    """
    Transformation in the Cipher that processes the State by cyclically
    shifting the last three rows of the State by different offsets.

    :param state: Intermediate Cipher result that can be pictured as a rectangular array
    of bytes, having four rows and Nb columns.
    :param inverse: Flag for inverse function
    """
    if not inverse:
        for i in range(len(state)):
            state[i] = state[i][i:] + state[i][:i]
    else:
        for i in range(len(state)):
            state[i] = state[i][(4-i):] + state[i][:(4-i)]


def mix_columns(state, inverse=False):
    """
    Transformation in the Cipher that takes all of the columns of the
    State and mixes their data (independently of one another) to
    produce new columns
    :param state: Intermediate Cipher result that can be pictured as a rectangular array
    of bytes, having four rows and Nb columns.
    :param inverse: Flag for inverse function
    """
    for i in range(4):
        a0 = state[0][i]
        a1 = state[1][i]
        a2 = state[2][i]
        a3 = state[3][i]
        b = mult_matrix(a0, a1, a2, a3, inverse)
        state[0][i] = b[0]
        state[1][i] = b[1]
        state[2][i] = b[2]
        state[3][i] = b[3]


def add_round_key(state, key):
    """
     Transformation in the Cipher and Inverse Cipher in which a Round
    Key is added to the State using an XOR operation. The length of a
    Round Key equals the size of the State (i.e., for Nb = 4, the Round
    Key length equals 128 bits/16 bytes).

    :param state: Intermediate Cipher result that can be pictured as a rectangular array
    of bytes, having four rows and Nb columns.

    :param key: Round keys are values derived from the Cipher Key using the Key
    Expansion routine; they are applied to the State in the Cipher and
    Inverse Cipher.

    """
    key = to_matrix(key)
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] ^= key[i][j]


def sub_word(word):
    """
    A function that takes a four-byte input word and applies the S-box
    to each of the four bytes to produce an output word
    :param word:  A group of 32 bits that is treated either as a single entity
    or as an array of 4 bytes.
    :return: changed word
    """
    changed_word = 0
    for i in range(24, -1, -8):
        byte = (word >> i) & 0xff
        changed_word = (changed_word << 8) + look_up(byte)
    return changed_word


def rot_word(word, rot):
    """
    Function used in the Key Expansion routine that takes a four-byte
    word and performs a cyclic permutation.

    :param word: A group of 32 bits that is treated either as a single entity
    or as an array of 4 bytes.
    :param rot: An integer that determines how many bytes
    the permutation takes place
    """
    msb = word >> (32 - 8 * rot)
    word = (((word << 8 * rot) & 0xffffff00) | msb)
    return word


def key_expansion(key):
    """
    Routine used to generate a series of Round Keys from the Cipher Key.
    :param key: Secret, cryptographic key that is used by the Key Expansion routine to
    generate a set of Round Keys; can be pictured as a rectangular array of
    bytes, having four rows and Nk columns.

    :return: word - A group of 32 bits that is treated either as a single entity
    or as an array of 4 bytes.

    """
    num_byte = len(key)
    N_k = num_byte // 4
    N_r = N_k + 6
    word = [()]*(N_b * (N_r + 1))

    for i in range(N_k):
        word[i] = byte_list_to_word((key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]))

    for i in range(N_k,(N_b * (N_r + 1))):
        temp = word[i - 1]
        if (i % N_k) == 0:
            temp = sub_word(rot_word(temp, 1)) ^ rcon[i // N_k]
        elif (N_k > 6 and i % N_k == 4):
            temp = sub_word(temp)
        word[i] = word[i - N_k] ^ temp
    return word


def cipher(state, state_out, word):
    """
    Series of transformations that converts plaintext to ciphertext using the
    Cipher Key.

    :param state: Data input to the Cipher.
    :param state_out: Data output from the Cipher.
    :param word: A group of 32 bits that is treated either as a single entity
    or as an array of 4 bytes.
    """
    N_r = len(word) // 4 - 1

    state = to_matrix(state)

    add_round_key(state, words_to_key(word, 0, N_b - 1))

    for i in range(1, N_r):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, words_to_key(word, i * N_b, (i + 1) * N_b - 1))

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, words_to_key(word, N_r * N_b, (N_r + 1) * N_b - 1))

    state_out[:] = to_list(state)


def inv_cipher(state, state_out, word):
    """
    Series of transformations that converts ciphertext to plaintext using the
    Cipher Key.

    :param state: Data input to the Inverse Cipher
    :param state_out: Data output from the Inverse Cipher.
    :param word: A group of 32 bits that is treated either as a single entity
    or as an array of 4 bytes.
    """
    N_r = len(word) // 4 - 1

    state = to_matrix(state)

    add_round_key(state, words_to_key(word, N_r * N_b, (N_r + 1) * N_b - 1))

    for i in range(N_r-1, 0, -1):
        shift_rows(state, True)
        sub_bytes(state, True)

        add_round_key(state, words_to_key(word, i * N_b, (i + 1) * N_b - 1))
        mix_columns(state, True)

    shift_rows(state, True)
    sub_bytes(state, True)
    add_round_key(state, words_to_key(word, 0, N_b - 1))

    state_out[:] = to_list(state)
