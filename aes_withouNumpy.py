import os
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
        self.table_exp = [0] * 512 # Exponentiation table
        self.table_log = [0] * 256 # Logarithm table
        self.generator = self._encontrar_generador() # Find a valid generator
        self._crear_tablas() # Create tables for fast operations
    
    
    def _encontrar_generador(self) -> int:
        """
        Tries different numbers to find a valid generator that covers all elements in the field.
        """
        for candidate in range(2, 256):
            seen_elements = set() # By definition, in a set there are no repetitions
            element = 1
            
            for _ in range(255):
                seen_elements.add(element)
                element = self.producto_lento(element, candidate) # Multiply using slow method
            
            if len(seen_elements) == 255: # If the candidate has different results for each power, then it's a valid generator
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
            x = self.producto_lento(x, self.generator) # Generate next power of the generator
    
        # We fill a duplicated table so that it won't be necessary to substract exponents when calculating the 'producto rápido'
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
    Reference document:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    The names of the methods, tables, etc. are the same (except for capitalization)
    as those used in FIPS 197
"""

    def __init__(self, key, polinomio_irreducible=0x11B) -> None:
        """
        Input:
        key: bytearray of 16, 24, or 32 bytes
        Polinomio_Irreducible: Integer representing the polynomial used to construct the field
        SBox: equivalent to table 4, p. 14
        InvSBox: equivalent to table 6, p. 23
        Rcon: equivalent to table 5, p. 17
        InvMixMatrix: equivalent to the matrix used in 5.3.3, p. 24
        """
        self.G_F = G_F(polinomio_irreducible) # Initialize Galois Field
        self.SBox, self.InvSBox = self._get_SBox() # Calculate SBox and InvSBox
        self.key = key 
        self.Nr = self._get_Nr(key) # Determine the number of rounds
        self.expanded_key = self.KeyExpansion(self.key) # Expand the key for all rounds

    @classmethod
    def print_array(cls, array, row_len=0, format="hex"):
        """
        Prints a one-dimensional array in specified format (hex, binary or decimal).
        """
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
        """
        Prints a two-dimensional matrix in specified format (hex, binary or decimal).
        """
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
        """
        Determines the number of rounds based on the key length. 
        """
        key_length = len(key)
        if key_length == 16: # AES-128
            return 10
        elif key_length == 24: # AES-192
            return 12
        elif key_length == 32: # AES-256
            return 14
        else:
            raise ValueError("Invalid key length")


    def _get_SBox(self):
        """
        Generates the SBox and InvSBox used for byte substitution. 
        Implements the affine transformation to create these tables.
        """
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
                b = affine_matrix[j] & inverse # Apply the affine transformation
                bit = 0
                while b > 0:
                    bit ^= (b & 1) # XOR all bits
                    b >>= 1
                bits = (bits << 1) | bit # Construct the transformed value
            result = bits ^ affine_const # Apply the affine constant

            SBox[i] = result
            InvSBox[result] = i
        
        return SBox, InvSBox


    def SubBytes(self, State):
        """
        Applies the SubBytes transformation to the state.
        Each byte is replaced with its corresponding value in SBox.
        """
        for i in range(4):
            for j in range(4): 
                number = State[i][j]
                State[i][j] = self.SBox[number] # Substitute using SBox
        return State


    def InvSubBytes(self, State):
        """
        Applies the InvSubBytes transformation to the state.
        Each byte is replaced with its corresponding value in InvSBox.
        """
        for i in range(4):
            for j in range(4):
                number = State[i][j]
                State[i][j] = self.InvSBox[number] # Substitute using InvSBox
        return State


    def ShiftRows(self, State):
        """
        Performs the ShiftRows transformation on the state.
        Each row is shifted left by its row index.
        """
        for i in range(4):
            State[i] = State[i][i:] + State[i][:i] # Shift row i
        return State


    def InvShiftRows(self, State):
        """
        Performs the InvShiftRows transformation on the state.
        Each row is shifted right by its row index.
        """
        for i in range(4):
            State[i] = State[i][-i:] + State[i][:-i] # Shift row i to the right
        return State


    def MixColumns(self, State):
        """
        Performs the MixColumns transformation on the state.
        Combines the bytes in each column using polynomial multiplication.
        """
        n1 = 0x01
        n2 = 0x02
        n3 = 0x03

        for col in range(4):
            s0 = State[0][col]
            s1 = State[1][col]
            s2 = State[2][col]
            s3 = State[3][col]

            # Calculate new values for each row in the column
            State[0][col] = self.G_F.producto(n2, s0) ^ self.G_F.producto(n3, s1) ^ s2 ^ s3
            State[1][col] = s0 ^ self.G_F.producto(n2, s1) ^ self.G_F.producto(n3, s2) ^ s3
            State[2][col] = s0 ^ s1 ^ self.G_F.producto(n2, s2) ^ self.G_F.producto(n3, s3)
            State[3][col] = self.G_F.producto(n3, s0) ^ s1 ^ s2 ^ self.G_F.producto(n2, s3)
        
        return State


    def InvMixColumns(self, State):
        """
        Performs the InvMixColumns transformation on the state.
        Reverses the MixColumns transformation using polynomial multiplication.
        """
        ne = 0x0e
        nb = 0x0b
        nd = 0x0d
        n9 = 0x09

        for col in range(4):
            s0 = State[0][col]
            s1 = State[1][col]
            s2 = State[2][col]
            s3 = State[3][col]

            # Calculate new values for each row in the column
            State[0][col] = self.G_F.producto(ne, s0) ^ self.G_F.producto(nb, s1) ^ self.G_F.producto(nd, s2) ^ self.G_F.producto(n9, s3)
            State[1][col] = self.G_F.producto(n9, s0) ^ self.G_F.producto(ne, s1) ^ self.G_F.producto(nb, s2) ^ self.G_F.producto(nd, s3)
            State[2][col] = self.G_F.producto(nd, s0) ^ self.G_F.producto(n9, s1) ^ self.G_F.producto(ne, s2) ^ self.G_F.producto(nb, s3)
            State[3][col] = self.G_F.producto(nb, s0) ^ self.G_F.producto(nd, s1) ^ self.G_F.producto(n9, s2) ^ self.G_F.producto(ne, s3)
        
        return State


    def AddRoundKey(self, State, roundKey):
        """
        Performs the AddRoundKey transformation by XORing the state with the round key.
        """
        for i in range(4):
            for j in range(4):
                State[i][j] ^= roundKey[i][j]
        return State
    

    def RotWord(self, word):
        """
        Shifts the given column of four bytes one position to the left.
        """
        rot_word = word[1:] + word[:1]
        return rot_word
    

    def SubWord(self, word):
        """
        Applies the SubBytes transformation to a given column of four bytes.
        """
        sub_word = [self.SBox[element] for element in word]
        return sub_word


    def KeyExpansion(self, key):
        """
        Expands the key into a series of round keys for use in each round.
        """
        Rcon = [1, 0, 0, 0] # First column of the Rcon matrix
        Nk = len(key) // 4 # Number of columns of each block given the key length
        expanded_key = []
        
        # Initial addition of the given key to the expanded_key in arrays of 4 positions (the rows of the expanded_key)
        for i in range(Nk):
            expanded_key.append(key[4*i : 4*i + 4])

        # Key expansion process
        for i in range(Nk, 4 * self.Nr + 4):
            temp = expanded_key[i-1] # Select the last column

            # If it's the first column of the block (varies according to the length of the key)
            if i % Nk == 0: 
                temp = self.SubWord(self.RotWord(temp)) # Shift left and substitute with SBox
                temp = [a ^ b for a,b in zip(temp, Rcon)] # XOR with Rcon
                Rcon[0] = self.G_F.xTimes(Rcon[0]) # Update Rcon
            # If the key is of length 32, Nk = 8, apply an extra subword every second fourth column 
            elif Nk > 6 and i % Nk == 4:
                temp = self.SubWord(temp) 

            # Apply for columns that aren't first in their block
            new_word = [a ^ b for a,b in zip(expanded_key[i - Nk], temp)] # XOR with the column in position i - Nk (size of the block)
            expanded_key.append(new_word)

        # Rearrange expanded keys into blocks
        expanded_key_blocks = []
        for i in range(0, (self.Nr + 1) * 4, 4):
            block = []
            for col in expanded_key[i:i+4]:
                block += col
            expanded_key_blocks.append(self._array_to_block(block)) # Convert the key into an array of 2D arrays
        return expanded_key_blocks


    def Cipher(self, State, Nr, Expanded_KEY): 
        """
        Performs the AES encryption on the state.
        Applies a series of transformations for the specified number of rounds.
        """
        State = self.AddRoundKey(State, Expanded_KEY[0]) # Initial round key addition
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
        """
        Performs the AES decryption on the state.
        Applies the inverse transformations for the specified number of rounds.
        """
        State = self.AddRoundKey(State, Expanded_KEY[-1]) # Initial round key addition
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
        """
        Adds PKCS7 padding to the data to make its length a multiple of the block size.
        """
        padding_length = block_size - (len(data) % block_size) # Calculate padding length
        if padding_length == 0: # If the data has already a size multiple of 16
            padding_length = 16 # Add 16 bytes of padding so we always add padding
        padding = bytes([padding_length]) * padding_length # Create padding bytes
        return data + padding


    def _array_to_block(self, array, row=4, col=4):
        """
        Converts a one-dimensional array into a 4x4 block format (list of lists).
        """
        block = [[0] * col for _ in range(row)]
        for j in range(col):
            for i in range(row):
                block[i][j] = array[j * col + i]
        return block


    def _split_into_blocks(self, data, add_padding=True, block_size=16):
        """
        Splits the input data into blocks of a specified size.
        Optionally adds padding to ensure the data is a multiple of the block size.
        """
        if add_padding:
            data = self._add_padding(data, block_size) # Add padding if required
        array = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            block = self._array_to_block(block)
            array.append(block)
        return array


    def encrypt_file(self, file): 
        """
        Input: Name of the file to encrypt
        Output: File encrypted using the key provided in the class constructor.
        CBC mode will be used for encryption, with an IV generated randomly
        and stored in the first 16 bytes of the encrypted file.
        The padding used will be PKCS7.
        The encrypted file name will be the original file name with the suffix .enc added:
        FileName --> FileName.enc
        """

        with open(file, 'rb') as data:
            blocks = self._split_into_blocks(data.read()) # Read and split data into blocks

        IV = os.urandom(16) # Generate random IV
        iv_block = self._array_to_block(IV) # Convert IV to block format

        cipher_blocks = []
        prev_block = iv_block # Initialize previous block with IV

        for block in blocks:
            xor_block = self.AddRoundKey(block, prev_block) # XOR with previous block
            encrypted_block = self.Cipher(xor_block, self.Nr, self.expanded_key) # Encrypt block
            cipher_blocks.append(encrypted_block) # Store encrypted block
            prev_block = encrypted_block

        encrypted_filename = file + '.enc' # Create encrypted file name
        with open(encrypted_filename, 'wb') as enc_file:
            enc_file.write(bytes(IV)) # Write IV to file
            for block in cipher_blocks:
                for i in range(4):
                    col = [row[i] for row in block]
                    enc_file.write(bytes([number for number in col]))


    def decrypt_file(self, file): 
        """
        Input: Name of the file to decrypt
        Output: File decrypted using the key provided in the class constructor.
        CBC mode will be used for decryption, with the IV stored in the first
        16 bytes of the encrypted file, and the PKCS7 padding added during encryption
        will be removed.
        The decrypted file name will be the original file name with the suffix .dec added:
        FileName --> FileName.dec
        """

        with open(file, 'rb') as enc_file:
            # Read and split file into 4x4 blocks and
            # transpose it so that it is in columns
            blocks = self._split_into_blocks(enc_file.read(), add_padding=False) 
        
        iv_block = blocks[0] # The first block is the IV
        encrypted_blocks = blocks[1:] # Remaining blocks are the encrypted data

        decrypted_blocks = []
        prev_block = iv_block # Initialize previous block with IV

        # Decrypt each block using CBC 
        for block in encrypted_blocks:
            decrypted_block = self.InvCipher(copy.deepcopy(block), self.Nr, self.expanded_key) # Decrypt block
            original_block = self.AddRoundKey(decrypted_block, prev_block) # XOR with previous block
            decrypted_blocks.append(original_block) # Store original block
            prev_block = block

        Bytes = []
        for block in decrypted_blocks: 
            for i in range(4):
                col = [row[i] for row in block] # Extract column
                Bytes.append(bytes([number for number in col])) # Convert to bytes and store
        decrypted_data = b''.join(Bytes) # Join all bytes into a single byte string

        # Remove PKCS7 padding
        padding_length = decrypted_data[-1] # Get padding length from last byte
        decrypted_data = decrypted_data[:-padding_length] # Remove padding

        decrypted_filename = file + '.dec' # Create decrypted file name
        with open(decrypted_filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)
