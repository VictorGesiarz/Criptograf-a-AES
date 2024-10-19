from cuerpo_finito import G_F, FiniteNumber
from aes import AES
import numpy as np


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


def test_steps(State, cipher_key):
    AES.print_matrix(State)
    print()

    SubBytes_state = algorithm.SubBytes(State)
    print(SubBytes_state.shape)
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

    roundKey = algorithm.KeyExpansion(cipher_key)
    AddRoundKey_state = algorithm.AddRoundKey(MixColumns_state, roundKey)
    AES.print_matrix(AddRoundKey_state)
    print()


def test_key_expansion(key):
    AES.print_matrix(key)
    print()

    Expanded_key = algorithm.KeyExpansion(key)
    AES.print_matrix(Expanded_key)
    print()

    Expanded_key2 = algorithm.KeyExpansion(Expanded_key)
    AES.print_matrix(Expanded_key2)


def test_cipher(state, key):
    print("STATE")
    AES.print_matrix(state)
    print("\nKEY")
    AES.print_matrix(key)
    print()

    cipher_state, expanded_key = algorithm.Cipher(state, 10, key)
    print("CIPHER STATE")
    AES.print_matrix(cipher_state)
    print()
    print("EXPANDED KEY")
    AES.print_matrix(expanded_key)
    print()


State_to_cipher = FiniteNumber.matrix_to_FN(np.array([
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34]
]), algorithm.G_F)

Cipher_key = FiniteNumber.matrix_to_FN(np.array([
    [0x2b, 0x28, 0xab, 0x09],
    [0x7e, 0xae, 0xf7, 0xcf],
    [0x15, 0xd2, 0x15, 0x4f],
    [0x16, 0xa6, 0x88, 0x3c]
]), algorithm.G_F)

test_cipher(State_to_cipher, Cipher_key)