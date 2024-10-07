from cuerpo_finito import G_F, FiniteNumber
from aes import AES


algorithm = AES(key=bytearray(16))
FiniteNumber.set_format('hex')

for i in range(16):
    for j in range(16):
        print(algorithm.SBox[i][j], end=", ")
    print()

