from cuerpo_finito import G_F, FiniteNumber


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
        self.polinomio_irreducible = polinomio_irreducible
        self.G_F = G_F(polinomio_irreducible)
        self.SBox = self._get_SBox()
        self.InvSBox = []
        self.Rcon = None
        self.InvMixMatrix = []


    def _get_SBox(self):
        SBox = [0] * 256
        affine_matrix = [0b11111000, 0b01111100, 0b00111110, 0b00011111, 0b10001111, 0b11000111, 0b11100011, 0b11110001]
        affine_const = FiniteNumber(0x63, self.G_F)
        
        SBox[0] = affine_const
        for i in range(1, 256):
            number = FiniteNumber(i, self.G_F)
            inverse = number.inverse()
            
            bits = 0
            for j in range(8):
                b = FiniteNumber(affine_matrix[j] & inverse.number, self.G_F).xor_bits()
                bits = (bits << 1) | b
            result = FiniteNumber(bits, self.G_F) + affine_const
            SBox[number.number] = result
        return SBox


    def SubBytes(self, State): ...

    def InvSubBytes(self, State): ... 

    def ShiftRows(self, State): ... 

    def InvShiftRows(self, State): ... 

    def MixColumns(self, State): ...

    def InvMixColumns(self, State): ...

    def AddRoundKey(self, State, roundKey): ...

    def KeyExpansion(self, key): ...

    def Cipher(self, State, Nr, Expanded_KEY): ...

    def InvChiper(self, State, Nr, Expanded_KEY): ...

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
