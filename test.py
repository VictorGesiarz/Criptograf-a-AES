import time
import random
import aes_withouNumpy as aes

Polinonios_Irreducibles=[0x11b, 0x1f9]
NKs = [16]


fichero = './ValoresTest/Test/mandril.png'


for nk in NKs:
    key = bytearray([random.randint(0,255) for _ in range(nk)])
    for polinomio in Polinonios_Irreducibles:
        print(f'\nPolinomio: {hex(polinomio)}, Nk: {nk}')
        aes_alumno = aes.AES(key, polinomio)

        t0=time.time()
        aes_alumno.encrypt_file(fichero)
        t1 = round(time.time()-t0, 2)
        print(f'Tiempo cifrado:  {t1}')
        if t1>15:
            print(f'----> Un tiempo superior a 15 segundos no es razonable.' )


        t0=time.time()
        aes_alumno.decrypt_file(fichero+'.enc')
        t1 = round(time.time()-t0, 2)
        print(f'Tiempo descifrado:  {t1}' )
        if t1>20:
            print(f'----> Un tiempo superior a 20 segundos no es razonable.' )

        with open(fichero, 'rb') as f:
            f1 = f.read()
        with open(fichero+'.enc.dec', 'rb') as f:
            f2 = f.read()

        print(f'Coinciden fichero original y fichero cifrado/descifrado? {f1 == f2}\n')

