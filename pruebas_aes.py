from cuerpo_finito import G_F
from aes_withouNumpy import AES
# from aes import AES
import numpy as np

# Key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
# Key = np.array([0x48, 0x87, 0xd4, 0x19, 0x3e, 0x4b, 0xc8, 0xc8, 0xd8, 0x50, 0xc1, 0xe1, 0x2a, 0xdc, 0xb3, 0xab])
# Key = np.array([0x26, 0x5f, 0x23, 0xdd, 0xc4, 0xdf, 0xc4, 0x3f, 0x00, 0xf8, 0x40, 0x1f, 0x44, 0x6d, 0x6c, 0x81])
Key = [0x18, 0x4d, 0x02, 0x14, 
       0xaf, 0xe9, 0x45, 0xd3, 
       0x15, 0x33, 0x9b, 0x6d, 
       0x92, 0xb0, 0x1c, 0x0f]
# Key = [0x18, 0xaf, 0x15, 0x92, 0x4d, 0xe9, 0x33, 0xb0, 0x02, 0x45, 0x9b, 0x1c, 0x14, 0xd3, 0x6d, 0x0f]
# Key = [0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05]
algorithm = AES(key=Key, polinomio_irreducible=0x11B)

State = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8], 
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08]
]


def test_steps(State):
    AES.print_matrix(State)
    print()

    SubBytes_state = algorithm.SubBytes(State)
    AES.print_matrix(SubBytes_state)
    print()

    # InvSBytes_states = algorithm.InvSubBytes(SubBytes_state)
    # AES.print_matrix(InvSBytes_states)
    # print()

    ShiftRows_state = algorithm.ShiftRows(SubBytes_state)
    AES.print_matrix(ShiftRows_state)
    print()

    # InvSRow_state = algorithm.InvShiftRows(ShiftRows_state)
    # AES.print_matrix(InvSRow_state)
    # print()

    MixColumns_state = algorithm.MixColumns(ShiftRows_state)
    AES.print_matrix(MixColumns_state)
    print()

    # InvMCol_state = algorithm.InvMixColumns(MixColumns_state)
    # AES.print_matrix(InvMCol_state)

    AddRoundKey_state = algorithm.AddRoundKey(MixColumns_state, algorithm.expanded_key[0])
    AES.print_matrix(AddRoundKey_state)
    print()


def test_key_expansion():
    expanded_keys = algorithm.KeyExpansion(algorithm.key)
    for expanded_key in expanded_keys:
        AES.print_matrix(expanded_key)
        print()


def test_cipher(state):
    print("STATE")
    AES.print_matrix(state)
    print()

    cipher_state = algorithm.Cipher(state, algorithm.Nr, algorithm.expanded_key)
    print("CIPHER STATE")
    AES.print_matrix(cipher_state)
    print()

    invcipher_state = algorithm.InvCipher(cipher_state, algorithm.Nr, algorithm.expanded_key)
    print("DECHIPERED STATE")
    AES.print_matrix(invcipher_state)
    print()


State_to_cipher = [
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34]
]

# test_steps(State)
# test_key_expansion()
# test_cipher(State_to_cipher)

# algorithm.encrypt_file('./ValoresTest/Test/mandril.png')
algorithm.decrypt_file('./ValoresTest/Test/mandril.png.enc')
