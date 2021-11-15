import filecmp
import unittest
from wrapper import create_file_with_random_letters, CBC
from Crypto.Cipher import AES as AESCrypto
import aes
from aes import AES
from utils import random_key_generator


class AesTest(unittest.TestCase):

    def test_encrypt_and_decrypt_small(self):
        text_to_cipher = "00112233445566778899aabbccddeeff"
        key_length = 128
        key = random_key_generator(key_length)

        self.AES_128 = AES(key)
        cipher = self.AES_128.cipher(text_to_cipher)

        cipher_pycrypto = AESCrypto.new(bytes.fromhex(key), AESCrypto.MODE_ECB)
        ciphertext = cipher_pycrypto.encrypt(bytes.fromhex(text_to_cipher))

        self.assertEqual(cipher, ciphertext.hex())

        text = self.AES_128.inv_cipher(cipher)

        self.assertEqual(text, text_to_cipher)

    def test_encrypt_and_decrypt_big(self):
        input_file = "plaintext.txt"
        output_file = 'encrypted.txt'
        create_file_with_random_letters(input_file, 2*1024*1024 + 2)
        key_length = 128
        key = random_key_generator(key_length)

        AES = aes.AES(key, 128)
        bcm = CBC(AES, 16)
        bcm.encrypt(input_file, output_file)
        out = 'decrypted.txt'
        bcm.decrypt(output_file, out)

        self.assertTrue(filecmp.cmp(input_file, out, shallow=False), 'Error files r not the same')


if __name__ == "__main__":
    unittest.main()
