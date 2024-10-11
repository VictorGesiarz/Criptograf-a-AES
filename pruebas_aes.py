from cuerpo_finito import G_F, FiniteNumber
from aes import AES


algorithm = AES(key=bytearray(16))
FiniteNumber.set_format('hex')

for i, number in enumerate(algorithm.SBox):
    print(number, end='\n' if (i % 16 == 15) else ' ')