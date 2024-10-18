from cuerpo_finito import G_F, FiniteNumber
from aes import AES
import numpy as np


def print_array(array, row_len=0):
    for i, number in enumerate(array):
        print(number, end='\n' if (i % 16 == 15) else ' ')

def print_matrix(matrix):
    for i in matrix:
        for j in i:
            print(j, end=" ")
        print()


FiniteNumber.set_format('hex')
algorithm = AES(key=bytearray(16))

State = FiniteNumber.matrix_to_FN(np.array([
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8], 
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08]
]), algorithm.G_F)

Cipher_key = FiniteNumber.matrix_to_FN(np.array([
    [0x2b, 0x28, 0xab, 0x09],
    [0x7e, 0xae, 0xf7, 0xcf],
    [0x15, 0xd2, 0x15, 0x4f],
    [0x16, 0xa6, 0x88, 0x3c]
]), algorithm.G_F)


def test_steps(state):
    print_matrix(State)
    print()

    SubBytes_state = algorithm.SubBytes(State)
    print(SubBytes_state.shape)
    print_matrix(SubBytes_state)
    print()

    # InvSBytes_states = algorithm.InvSubBytes(SubBytes_state)
    # print_matrix(InvSBytes_states)
    # print()

    ShiftRows_state = algorithm.ShiftRows(SubBytes_state)
    print_matrix(ShiftRows_state)
    print()

    # InvSRow_state = algorithm.InvShiftRows(ShiftRows_state)
    # print_matrix(InvSRow_state)
    # print()

    MixColumns_state = algorithm.MixColumns(ShiftRows_state)
    print_matrix(MixColumns_state)
    print()

    # InvMCol_state = algorithm.InvMixColumns(MixColumns_state)
    # print_matrix(InvMCol_state)

    AddRoundKey_state = algorithm.AddRoundKey(MixColumns_state, Cipher_key)
    print_matrix(AddRoundKey_state)
    print()


def test_key_expansion(key):
    print_matrix(key)
    print()

    Expanded_key = algorithm.KeyExpansion(key)
    print_matrix(Expanded_key)
    print()

    Expanded_key2 = algorithm.KeyExpansion(Expanded_key)
    print_matrix(Expanded_key2)


# test_key_expansion(Cipher_key)
test_steps(State)