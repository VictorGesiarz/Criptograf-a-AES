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
    [0xd4, 0xe0, 0xb8, 0x1e],
    [0xbf, 0xb4, 0x41, 0x27], 
    [0x5d, 0x52, 0x11, 0x98],
    [0x30, 0xae, 0xf1, 0xe5]
]

State = FiniteNumber.matrix_to_FN(State, algorithm.G_F)
print_FN_matrix(State)
print()

NewState = algorithm.MixColumns(State)
print_FN_matrix(NewState)