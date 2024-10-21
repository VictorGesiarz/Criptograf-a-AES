import numpy as np
import os
import time
import copy


class G_F:
    """
    Generates a finite field using the given irreducible polynomial represented as an integer.
    By default, it uses the AES polynomial. The elements of the field are represented by integers 0 <= n <= 255.
    """
    
    def __init__(self, polinomio_irreducible=0x11B) -> None:
        """
        Initializes the field with the given irreducible polynomial.
        Also creates the EXP and LOG tables for efficient multiplication and inversion.
        """
        self.polinomio_irreducible = polinomio_irreducible
        self.table_exp = [0] * 512 
        self.table_log = [0] * 256
        self.generator = self._encontrar_generador()
        self._crear_tablas()
    

    def _encontrar_generador(self) -> int:
        """
        Tries different numbers to find a valid generator that covers all elements in the field.
        """
        for candidate in range(2, 256):
            seen_elements = set()
            element = 1
            
            for _ in range(255):
                seen_elements.add(element)
                element = self.producto_lento(element, candidate)
            
            if len(seen_elements) == 255:
                return candidate
        raise ValueError("No valid generator found")


    def _crear_tablas(self) -> None:
        """
        Creates the EXP and LOG tables using the found generator.
        """
        x = 1 
        for i in range(255):
            self.table_exp[i] = x 
            self.table_log[x] = i 
            x = self.producto_lento(x, self.generator)
    
        for i in range(255, 512):
            self.table_exp[i] = self.table_exp[i - 255]
		

    def suma(self, a, b) -> int:
        """
        Returns the sum (XOR) of two elements in the field.
        """
        return a ^ b


    def xTimes(self, n) -> int:
        """
        Multiplies a given element n by the polynomial X (i.e., shifts left and reduces if needed).
        """
        result = n << 1
        if result >= 256:
            result ^= self.polinomio_irreducible
        return result
    

    def producto_lento(self, a, b) -> int:
        """
        Multiplies 2 polynomials the slow way. 
        """
        result = 0
        while b > 0:
            if b & 1: 
                result ^= a 
            a = self.xTimes(a) 
            b >>= 1 
        return result


    def producto(self, a, b) -> int:
        """
        Returns the product of two elements in the field using the EXP and LOG tables for efficiency.
        """
        if a == 0 or b == 0:
            return 0
        log_sum = self.table_log[a] + self.table_log[b]
        return self.table_exp[log_sum]
    

    def inverso(self, n) -> int:
        """
        Returns the multiplicative inverse of n in the field. If n == 0, returns 0.
        """
        if n == 0:
            return 0
        log_n = self.table_log[n]
        inv_log = 255 - log_n
        return self.table_exp[inv_log]
    

    def division(self, a, b) -> int: 
        """
        Returns the division between a and b.
        """
        if a == 0 or b == 0:
            return 0
        log_sum = self.table_log[a] - self.table_log[b]
        return self.table_exp[log_sum]


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
        self.key = self._array_to_block(key)
        self.Nr = self._get_Nr(key)
        self.expanded_key = self.KeyExpansion(self.key)

    @classmethod
    def print_array(cls, array, row_len=0, format="hex"):
        for i, j in enumerate(array):
            if format == "hex":
                s = f'{j:02X}'
            elif format == "bin":
                s = f'{j:0b}'
            else:
                s = j
            print(s, end='\n' if (i % row_len == row_len-1) else ' ')

    @classmethod
    def print_matrix(cls, matrix, format="hex"):
        for i in matrix:
            for j in i:
                if format == "hex":
                    s = f'{j:02X}'
                elif format == "bin":
                    s = f'{j:0b}'
                else:
                    s = j
                print(s, end=" ")
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
        affine_const = 0x63
        
        SBox[0] = affine_const
        InvSBox[affine_const] = 0
        for i in range(1, 256):
            inverse = self.G_F.inverso(i)
        
            bits = 0
            for j in range(8):
                # b = ((inverse >> j) & 1) ^ \
                #     ((inverse >> (j + 4) % 8) & 1) ^ \
                #     ((inverse >> (j + 5) % 8) & 1) ^ \
                #     ((inverse >> (j + 6) % 8) & 1) ^ \
                #     ((inverse >> (j + 7) % 8) & 1) ^ \
                #     ((affine_const.number >> j) & 1)
                b = affine_matrix[j] & inverse
                bit = 0
                while b > 0:
                    bit ^= (b & 1) 
                    b >>= 1
                bits = (bits << 1) | bit
            result = bits ^ affine_const

            SBox[i] = result
            InvSBox[result] = i
        
        return SBox, InvSBox


    def SubBytes(self, State):
        for i in range(4):
            for j in range(4): 
                number = State[i][j]
                State[i][j] = self.SBox[number]
        return State


    def InvSubBytes(self, State):
        for i in range(4):
            for j in range(4):
                number = State[i][j]
                State[i][j] = self.InvSBox[number]
        return State


    def ShiftRows(self, State):
        for i in range(4):
            State[i] = State[i][i:] + State[i][:i] 
        return State


    def InvShiftRows(self, State):
        for i in range(4):
            State[i] = State[i][-i:] + State[i][:-i]  
        return State


    def MixColumns(self, State):
        n1 = 0x01
        n2 = 0x02
        n3 = 0x03

        for col in range(4):
            s0 = State[0][col]
            s1 = State[1][col]
            s2 = State[2][col]
            s3 = State[3][col]

            State[0][col] = self.G_F.producto(n2, s0) ^ self.G_F.producto(n3, s1) ^ s2 ^ s3
            State[1][col] = s0 ^ self.G_F.producto(n2, s1) ^ self.G_F.producto(n3, s2) ^ s3
            State[2][col] = s0 ^ s1 ^ self.G_F.producto(n2, s2) ^ self.G_F.producto(n3, s3)
            State[3][col] = self.G_F.producto(n3, s0) ^ s1 ^ s2 ^ self.G_F.producto(n2, s3)
        
        return State


    def InvMixColumns(self, State): 
        ne = 0x0e
        nb = 0x0b
        nd = 0x0d
        n9 = 0x09

        for col in range(4):
            s0 = State[0][col]
            s1 = State[1][col]
            s2 = State[2][col]
            s3 = State[3][col]

            State[0][col] = self.G_F.producto(ne, s0) ^ self.G_F.producto(nb, s1) ^ self.G_F.producto(nd, s2) ^ self.G_F.producto(n9, s3)
            State[1][col] = self.G_F.producto(n9, s0) ^ self.G_F.producto(ne, s1) ^ self.G_F.producto(nb, s2) ^ self.G_F.producto(nd, s3)
            State[2][col] = self.G_F.producto(nd, s0) ^ self.G_F.producto(n9, s1) ^ self.G_F.producto(ne, s2) ^ self.G_F.producto(nb, s3)
            State[3][col] = self.G_F.producto(nb, s0) ^ self.G_F.producto(nd, s1) ^ self.G_F.producto(n9, s2) ^ self.G_F.producto(ne, s3)
        
        return State


    def AddRoundKey(self, State, roundKey): 
        for i in range(4):
            for j in range(4):
                State[i][j] ^= roundKey[i][j]
        return State


    def KeyExpansion(self, key): 
        Rcon = [1, 0, 0, 0]
        expanded_key = [key]

        for _ in range(self.Nr):
            previous_key = expanded_key[-1]
            new_round_key = [[0] * 4 for _ in range(4)]

            rot_word = [row[3] for row in previous_key]
            rot_word = rot_word[1:] + rot_word[:1] 
            rot_word = [self.SBox[element] for element in rot_word]

            for i in range(4):
                new_round_key[i][0] = previous_key[i][0] ^ rot_word[i] ^ Rcon[i]
            for i in range(1, 4):
                for j in range(4):
                    new_round_key[j][i] = previous_key[j][i] ^ new_round_key[j][i - 1]
            
            expanded_key.append(new_round_key)
            Rcon[0] = self.G_F.xTimes(Rcon[0])
        return expanded_key


    def Cipher(self, State, Nr, Expanded_KEY): 
        State = self.AddRoundKey(State, Expanded_KEY[0])
        for i in range(1, Nr):
            State = self.SubBytes(State)
            State = self.ShiftRows(State)
            State = self.MixColumns(State)
            State = self.AddRoundKey(State, Expanded_KEY[i])
        State = self.SubBytes(State)
        State = self.ShiftRows(State)
        State = self.AddRoundKey(State, Expanded_KEY[i + 1])
        return State


    def InvCipher(self, State, Nr, Expanded_KEY): 
        State = self.AddRoundKey(State, Expanded_KEY[-1])
        for i in range(Nr - 1, 0, -1):
            State = self.InvShiftRows(State)
            State = self.InvSubBytes(State)
            State = self.AddRoundKey(State, Expanded_KEY[i])
            State = self.InvMixColumns(State)
        State = self.InvShiftRows(State)
        State = self.InvSubBytes(State)
        State = self.AddRoundKey(State, Expanded_KEY[i - 1])
        return State


    def _add_padding(self, data, block_size=16):
        padding_length = block_size - (len(data) % block_size)
        if padding_length == 0:
            padding_length = 16
        padding = bytes([padding_length]) * padding_length
        return data + padding


    def _array_to_block(self, array, row=4, col=4):
        block = [[0] * col for _ in range(row)]
        for j in range(col):
            for i in range(row):
                block[i][j] = array[j * col + i]
        return block


    def _split_into_blocks(self, data, add_padding=True, block_size=16):
        if add_padding:
            data = self._add_padding(data, block_size)
        array = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            block = self._array_to_block(block)
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

        with open(file, 'rb') as data:
            blocks = self._split_into_blocks(data.read())

        IV = os.urandom(16)
        iv_block = self._array_to_block(IV)
        # IV = [250, 196, 220, 155, 142, 249, 166, 195, 63, 31, 50, 221, 236, 20, 206, 87]                          #
        # IV = [0x2a, 0x3c, 0x55, 0xec, 0xe2, 0x05, 0x81, 0x1e, 0x51, 0x9c, 0xfa, 0xa9, 0x0b, 0xd4, 0xf2, 0xde]     # ESto son solo valores test, el IV tiene que ser aleatorio
        # IV = [0xc2, 0x17, 0xd7, 0x20, 0x60, 0x14, 0x77, 0x14, 0xde, 0xd1, 0xfa, 0x90, 0xd5, 0xac, 0x90, 0x97]       #
        # iv_block = self._array_to_block(IV)

        cipher_blocks = []
        prev_block = iv_block 

        for block in blocks:
            xor_block = self.AddRoundKey(block, prev_block)
            encrypted_block = self.Cipher(xor_block, self.Nr, self.expanded_key)
            cipher_blocks.append(encrypted_block)
            prev_block = encrypted_block

        encrypted_filename = file + '.enc' # f"_0x{self.G_F.polinomio_irreducible:02X}_" + "".join([f'{i:02X}' for i in self.key.flatten()]) +
        with open(encrypted_filename, 'wb') as enc_file:
            enc_file.write(bytes(IV))
            for block in cipher_blocks:
                for i in range(4):
                    col = [row[i] for row in block]
                    enc_file.write(bytes([number for number in col]))


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

        with open(file, 'rb') as enc_file:
            # Leemos todo el fichero y lo separamos por bloques de 4x4 y 
            # hacemos la transpuesta para que esté por columnas
            blocks = self._split_into_blocks(enc_file.read(), add_padding=False)
        
        # El primer bloque es el IV y el resto son los datos cifrados
        iv_block = blocks[0]
        encrypted_blocks = blocks[1:]

        decrypted_blocks = []
        prev_block = iv_block

        # Desciframos cada bloque con CBC 
        for block in encrypted_blocks:
            decrypted_block = self.InvCipher(copy.deepcopy(block), self.Nr, self.expanded_key)
            original_block = self.AddRoundKey(decrypted_block, prev_block)
            decrypted_blocks.append(original_block)
            prev_block = block

        Bytes = []
        for block in decrypted_blocks: 
            for i in range(4):
                col = [row[i] for row in block]
                Bytes.append(bytes([number for number in col]))
        decrypted_data = b''.join(Bytes)
        # print(decrypted_data)

        # Eliminamos el padding PKCS7
        padding_length = decrypted_data[-1]
        
        # if padding_length > 0 and padding_length <= 16:
        decrypted_data = decrypted_data[:-padding_length]

        decrypted_filename = file + '.dec'
        with open(decrypted_filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)
