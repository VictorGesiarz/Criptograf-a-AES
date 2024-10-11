from cuerpo_finito import G_F, FiniteNumber
from aes import AES


def print_FN_matrix(matrix):
    for i in matrix:
        for j in i:
            print(j, end=" ")
        print()


algorithm = AES(key=bytearray(16))
FiniteNumber.set_format('hex')

State = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8], 
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08]
]

State = FiniteNumber.matrix_to_FN(State, algorithm.G_F)
print_FN_matrix(State)
print()

SubBytes_state = algorithm.SubBytes(State)
print_FN_matrix(SubBytes_state)
print()

ShiftRows_state = algorithm.ShiftRows(SubBytes_state)
print_FN_matrix(ShiftRows_state)
print()

MixColumns_state = algorithm.MixColumns(ShiftRows_state)
print_FN_matrix(MixColumns_state)