from cuerpo_finito import G_F, FiniteNumber
import numpy as np


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
        self.key = FiniteNumber.matrix_to_FN(np.reshape(key, (4, 4)), self.G_F)
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
            inverse = number.inverse()
            
            bits = 0
            for j in range(8):
                b = FiniteNumber(affine_matrix[j] & inverse.number, self.G_F).xor_bits()
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
        for j in range(State.shape[1]):
            for i in range(State.shape[0]):
                State[i, j] += roundKey[i, j]
        return State


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
