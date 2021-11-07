from aes import key_expansion, cipher, inv_cipher


def split_string_to_int(str):
    lst = []
    for i in range(0, len(str), 2):
        lst.append(int(str[i : i + 2], 16))
    return lst


def combine_int_list_to_string(lst):
    str = ''
    for int in lst:
        if int == 0:
            str += '00'
        str += format(int, 'x')
    return str


out = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
plaintext = '00112233445566778899aabbccddeeff'
key = '000102030405060708090a0b0c0d0e0f'
state = split_string_to_int(plaintext)
key = split_string_to_int(key)
w = key_expansion(key)
cipher(state, out, w)
new_state = out
result = combine_int_list_to_string(out)
print(result)
out = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
inv_cipher(new_state, out, w)
result = combine_int_list_to_string(out)
print(result)