from cuerpo_finito import G_F, FiniteNumber
import numpy as np
import os
import time

class AES: 
    """
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los m ́etodos, tablas, etc son los mismos (salvo capitalizaci ́on)
    que los empleados en el FIPS 197
    """

    def __init__(self, key, polinomio_irreducible=0x11B) -> None:
        """
        Entrada:
        key: bytearray de 16 24 o 32 bytes
        Polinomio_Irreducible: Entero que representa el polinomio para construir el cuerpo
        SBox: equivalente a la tabla 4, p ́ag. 14
        InvSBOX: equivalente a la tabla 6, p ́ag. 23
        Rcon: equivalente a la tabla 5, p ́ag. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, p ́ag. 24
        """
        self.G_F = G_F(polinomio_irreducible)
        self.SBox, self.InvSBox = self._get_SBox()
        self.key = FiniteNumber.matrix_to_FN(np.reshape(list(key), (4, 4)).T, self.G_F)
        self.Nr = self._get_Nr(key)
        self.expanded_key = self.KeyExpansion(self.key)

    @classmethod
    def print_array(cls, array, row_len=0):
        for i, number in enumerate(array):
            print(number, end='\n' if (i % 16 == 15) else ' ')

    @classmethod
    def print_matrix(cls, matrix):
        for i in matrix:
            for j in i:
                print(j, end=" ")
            print()


    def _get_Nr(self, key):
        key_lenght = len(key)
        if key_lenght == 16:
            return 10
        elif key_lenght == 24: 
            return 12
        elif key_lenght == 32:
            return 14
        else:
            raise ValueError("Invalid key lenght")


    def _get_SBox(self):
        SBox = [0] * 256
        InvSBox = [0] * 256
        affine_matrix = [0b11111000, 0b01111100, 0b00111110, 0b00011111, 0b10001111, 0b11000111, 0b11100011, 0b11110001]
        affine_const = FiniteNumber(0x63, self.G_F)
        
        SBox[0] = affine_const
        InvSBox[affine_const.number] = FiniteNumber(0, self.G_F)
        for i in range(1, 256):
            number = FiniteNumber(i, self.G_F)
            inverse = number.inverse().number
            
            bits = 0
            for j in range(8):
                # b = ((inverse >> j) & 1) ^ \
                #     ((inverse >> (j + 4) % 8) & 1) ^ \
                #     ((inverse >> (j + 5) % 8) & 1) ^ \
                #     ((inverse >> (j + 6) % 8) & 1) ^ \
                #     ((inverse >> (j + 7) % 8) & 1) ^ \
                #     ((affine_const.number >> j) & 1)
                b = FiniteNumber(affine_matrix[j] & inverse, self.G_F).xor_bits()
                bits = (bits << 1) | b
            result = FiniteNumber(bits, self.G_F) + affine_const

            SBox[number.number] = result
            InvSBox[result.number] = number
        
        return SBox, InvSBox


    def SubBytes(self, State):
        for j in range(State.shape[1]):
            for i in range(State.shape[0]): 
                number = State[i, j]
                State[i, j] = self.SBox[number.number]
        return State


    def InvSubBytes(self, State):
        for j in range(State.shape[0]):
            for i in range(State.shape[1]):
                number = State[i, j]
                State[i, j] = self.InvSBox[number.number]
        return State


    def ShiftRows(self, State):
        for i in range(4):
            State[i] = np.roll(State[i], -i) 
        return State


    def InvShiftRows(self, State):
        for i in range(4):
            State[i] = np.roll(State[i], i) 
        return State


    def MixColumns(self, State):
        n1 = FiniteNumber(0x01, self.G_F)
        n2 = FiniteNumber(0x02, self.G_F)
        n3 = FiniteNumber(0x03, self.G_F)

        for col in range(4):
            s0 = State[0, col]
            s1 = State[1, col]
            s2 = State[2, col]
            s3 = State[3, col]

            State[0, col] = n2 * s0 + n3 * s1 + s2 + s3
            State[1, col] = s0 + n2 * s1 + n3 * s2 + s3
            State[2, col] = s0 + s1 + n2 * s2 + n3 * s3
            State[3, col] = n3 * s0 + s1 + s2 + n2 * s3
        
        return State


    def InvMixColumns(self, State): 
        ne = FiniteNumber(0x0e, self.G_F)
        nb = FiniteNumber(0x0b, self.G_F)
        nd = FiniteNumber(0x0d, self.G_F)
        n9 = FiniteNumber(0x09, self.G_F)

        for col in range(4):
            s0 = State[0, col]
            s1 = State[1, col]
            s2 = State[2, col]
            s3 = State[3, col]

            State[0, col] = ne * s0 + nb * s1 + nd * s2 + n9 * s3
            State[1, col] = n9 * s0 + ne * s1 + nb * s2 + nd * s3
            State[2, col] = nd * s0 + n9 * s1 + ne * s2 + nb * s3
            State[3, col] = nb * s0 + nd * s1 + n9 * s2 + ne * s3
        
        return State


    def AddRoundKey(self, State, roundKey): 
        return State + roundKey


    def KeyExpansion(self, key): 
        Rcon = FiniteNumber.array_to_FN(np.array([1, 0, 0, 0], dtype=object), self.G_F)
        expanded_key = [key]

        for _ in range(self.Nr):
            previous_key = expanded_key[-1]
            new_round_key = np.empty(key.shape, dtype=object)

            rot_word = previous_key[:, 3]
            rot_word = np.roll(rot_word, -1) 
            rot_word = self.SubBytes(rot_word.reshape(1, 4)).flatten()

            new_round_key[:, 0] = previous_key[:, 0] + rot_word + Rcon
            for i in range(1, 4): 
                new_round_key[:, i] = previous_key[:, i] + new_round_key[:, i - 1]

            expanded_key.append(new_round_key)
            Rcon *= FiniteNumber(2, self.G_F)
        return expanded_key


    def Cipher(self, State, Nr, Expanded_KEY): 
        State = self.AddRoundKey(State, Expanded_KEY[0])
        for i in range(1, Nr + 1):
            State = self.SubBytes(State)
            State = self.ShiftRows(State)
            if i != Nr: 
                State = self.MixColumns(State)
            State = self.AddRoundKey(State, Expanded_KEY[i])
        return State


    def InvChiper(self, State, Nr, Expanded_KEY): 
        State = self.AddRoundKey(State, Expanded_KEY[-1])
        for i in range(Nr - 1, -1, -1):
            State = self.InvShiftRows(State)
            State = self.InvSubBytes(State)
            State = self.AddRoundKey(State, Expanded_KEY[i])
            if i != 0:
                State = self.InvMixColumns(State)
        return State


    def _add_padding(self, data, block_size=16):
        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = 16
        padding = bytes([padding_length]) * padding_length
        return data + padding


    def _split_into_blocks(self, data, block_size=16):
        data = self._add_padding(data, block_size)
        array = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            block = np.array(list(block), dtype=np.uint8)
            block = np.reshape(block, (4, 4)).T
            block = FiniteNumber.matrix_to_FN(block, self.G_F)
            array.append(block)
        return array


    def encrypt_file(self, file): 
        """
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor de la clase.
        Para cifrar se usará el modo CBC, con IV generado aleatoriamente
        y guardado en los 16 primeros bytes del fichero cifrado.
        El padding usado será PKCS7.
        El nombre de fichero cifrado será el obtenido al a~nadir el sufijo .enc
        al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        """

        start = time.time()

        with open('./ValoresTest/' + file, 'rb') as data:
            blocks = self._split_into_blocks(data.read())

        end = time.time()
        print(f'Tarda {end - start} segundos en separar en bloques')

        # IV = os.urandom(16)
        # iv_block = np.array(list(IV), dtype=np.uint8).reshape((4, 4))
        # IV = [250, 196, 220, 155, 142, 249, 166, 195, 63, 31, 50, 221, 236, 20, 206, 87]                          #
        IV = [0x2a, 0x3c, 0x55, 0xec, 0xe2, 0x05, 0x81, 0x1e, 0x51, 0x9c, 0xfa, 0xa9, 0x0b, 0xd4, 0xf2, 0xde]       # ESto son solo valores test, el IV tiene que ser aleatorio
        iv_block = np.array(IV).reshape((4, 4)).T
        iv_block = FiniteNumber.matrix_to_FN(iv_block, self.G_F)

        cipher_blocks = []
        prev_block = iv_block 

        for block in blocks:
            xor_block = block + prev_block
            encrypted_block = self.Cipher(xor_block, self.Nr, self.expanded_key)
            cipher_blocks.append(encrypted_block)
            prev_block = encrypted_block

        encrypted_filename = file + f"_0x{self.G_F.polinomio_irreducible:02X}_" + "".join([i.as_hex() for i in self.key.flatten()]) + '.enc'
        with open('./ValoresTest/Results/' + encrypted_filename, 'wb') as enc_file:
            enc_file.write(bytes(IV))
            for block in cipher_blocks:
                for col in block.T:
                    enc_file.write(bytes([number.number for number in col]))

        end = time.time()
        print(f"Archivo cifrado guardado como {encrypted_filename} in {round(end - start, 4)} seconds")


    def decrypt_file(self, file): 
        """
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.
        Para descifrar se usará el modo CBC, con el IV guardado en los 16
        primeros bytes del fichero cifrado, y se eliminará el padding
        PKCS7 añadido al cifrar el fichero.
        El nombre de fichero descifrado será el obtenido al añadir el sufijo .dec
        al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        """

        start = time.time() 

        with open('./ValoresTest/Results/' + file, 'rb') as enc_file:
            # Leemos todo el fichero y lo separamos por bloques de 4x4 y 
            # hacemos la transpuesta para que esté por columnas
            blocks = self._split_into_blocks(enc_file.read())
        
        # El primer bloque es el IV y el resto son los datos cifrados
        iv_block = blocks[0]
        encrypted_block = blocks[1:]

        decrypted_blocks = []
        prev_block = iv_block

        # Desciframos cada bloque con CBC 
        for block in encrypted_block: 
            decrypted_block = self.InvChiper(block, self.Nr, self.expanded_key)
            original_block = decrypted_block - prev_block
            decrypted_blocks.append(original_block)
            prev_block = block

        # Concatenamos todos los bloques 
        decrypted_data = b''.join(bytes([number.number for number in col]) for block in decrypted_blocks for col in block.T)

        # Eliminamos el padding PKCS7
        padding_length = decrypted_data[-1]
        # if padding_length > 0 and padding_length <= 16:
        decrypted_data = decrypted_data[:-padding_length]

        decrypted_filename = file.replace('.enc', '.dec')
        with open('./ValoresTest/Results/' + decrypted_filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        end = time.time()
        print(f"Archivo descifrado guardado como {decrypted_filename} en {round(end - start, 4)} seconds")