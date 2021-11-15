from constants import rcon, sbox, inv_sbox
from utils import mult_matrix, text2matrix, matrix2text


# https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
class AES:
    def __init__(self, key, mode=128):
        self.Nb = 4
        if mode == 192:
            self.Nk = 6
            self.Nr = 12
            self.key = text2matrix(key, 24)
        elif mode == 256:
            self.Nk = 8
            self.Nr = 14
            self.key = text2matrix(key, 32)
        else:
            self.Nk = 4
            self.Nr = 10
            self.key = text2matrix(key)

        self.key_expansion(self.key)

    def sub_bytes(self, state, inverse=False):
        """
        Transformation in the Cipher that processes the State using a non
        linear byte substitution table (S-box) that operates on each of the
        State bytes independently.

        :param state:Intermediate Cipher result that can be pictured as a rectangular array
        of bytes, having four rows and Nb columns.

        :param inverse: Flag for inverse function
        """
        for i in range(self.Nb):
            for j in range(4):
                state[i][j] = sbox[state[i][j]] if not inverse else inv_sbox[state[i][j]]

    def shift_rows(self, state, inverse=False):
        """
        Transformation in the Cipher that processes the State by cyclically
        shifting the last three rows of the State by different offsets.

        :param state: Intermediate Cipher result that can be pictured as a rectangular array
        of bytes, having four rows and Nb columns.
        :param inverse: Flag for inverse function
        """
        if not inverse:
            state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
            state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
            state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]
        else:
            state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]
            state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
            state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]

    def mix_columns(self, state, inverse=False):
        """
        Transformation in the Cipher that takes all of the columns of the
        State and mixes their data (independently of one another) to
        produce new columns
        :param state: Intermediate Cipher result that can be pictured as a rectangular array
        of bytes, having four rows and Nb columns.
        :param inverse: Flag for inverse function
        """
        for i in range(self.Nb):
            a0 = state[i][0]
            a1 = state[i][1]
            a2 = state[i][2]
            a3 = state[i][3]
            b = mult_matrix(a0, a1, a2, a3, inverse)
            state[i][0] = b[0]
            state[i][1] = b[1]
            state[i][2] = b[2]
            state[i][3] = b[3]


    def add_round_key(self, state, key):
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
        for i in range(self.Nb):
            for j in range(4):
                state[i][j] ^= key[i][j]

    def sub_word(self, word):
        """
        A function that takes a four-byte input word and applies the S-box
        to each of the four bytes to produce an output word
        :param word:  A group of 32 bits that is treated either as a single entity
        or as an array of 4 bytes.
        """
        for i in range(len(word)):
            word[i] = sbox[word[i]]

    def rot_word(self, word):
        """
        Function used in the Key Expansion routine that takes a four-byte
        word and performs a cyclic permutation.

        :param word: A group of 32 bits that is treated either as a single entity
        or as an array of 4 bytes.
        """
        word[0], word[1], word[2], word[3] = word[1], word[2], word[3], word[0]

    def key_expansion(self, key):
        """
        Routine used to generate a series of Round Keys from the Cipher Key.
        :param key: Secret, cryptographic key that is used by the Key Expansion routine to
        generate a set of Round Keys; can be pictured as a rectangular array of
        bytes, having four rows and Nk columns.
        """
        self.round_keys = self.key

        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            self.round_keys.append([0, 0, 0, 0])
            temp = self.round_keys[i - 1][:]
            # word is multiple of Nk
            if i % self.Nk == 0:
                self.rot_word(temp)
                self.sub_word(temp)
                temp[0] = temp[0] ^ rcon[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                """If Nk = 8 (AES-256) and i - 4 is multiple of Nk
                then SUbWord() is applied to word[i - 1] prior to
                the XOR. Nist Fips 192. Section 5.2"""
                self.sub_word(temp)

            for j in range(4):
                self.round_keys[i][j] = self.round_keys[i - self.Nk][j] ^ temp[j]

    def cipher(self, text):
        """
        Series of transformations that converts plaintext to ciphertext using the
        Cipher Key.
        :param text: Data input to the Cipher(plain text)
        :return state_out: Data output(encrypted) from the Cipher
        """
        self.state = text2matrix(text)

        self.add_round_key(self.state, self.round_keys[:4])

        for i in range(1, self.Nr):
            self.sub_bytes(self.state)
            self.shift_rows(self.state)
            self.mix_columns(self.state)
            self.add_round_key(self.state,
                               self.round_keys[self.Nb * i: self.Nb * (i + 1)])

        self.sub_bytes(self.state)
        self.shift_rows(self.state)
        self.add_round_key(self.state,
                           self.round_keys[len(self.round_keys) - 4:])

        return matrix2text(self.state)

    def inv_cipher(self, text):
        """
        Series of transformations that converts ciphertext to plaintext using the
        Cipher Key.
        :param text: Data input(encrypted) to the Inverse Cipher
        :return state_out: Data output(decrypted) from the Inverse Cipher
        """
        self.encrypted_state = text2matrix(text)

        self.add_round_key(self.encrypted_state,
                           self.round_keys[len(self.round_keys) - 4:])

        for i in range(self.Nr - 1, 0, -1):
            self.shift_rows(self.encrypted_state, True)
            self.sub_bytes(self.encrypted_state, True)
            self.add_round_key(self.encrypted_state,
                               self.round_keys[self.Nb * i: self.Nb * (i + 1)])
            self.mix_columns(self.encrypted_state, True)

        self.shift_rows(self.encrypted_state, True)
        self.sub_bytes(self.encrypted_state, True)
        self.add_round_key(self.encrypted_state, self.round_keys[:4])

        return matrix2text(self.encrypted_state)
