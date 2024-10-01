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
                print(f'Generator found: {candidate}')
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



class FiniteNumber:
    _display_format = "decimal" 

    def __init__(self, number, FiniteField, format='Decimal') -> None:
        self.FiniteField = FiniteField  # The finite field instance (e.g., G_F)
        self.number = number % 256  # Ensure the number is within the valid range of the field (0-255)
        self.format = format

    @classmethod
    def set_format(cls, display_format):
        """Sets the display format for all FiniteNumber instances."""
        if display_format not in {"decimal", "binary", "hex"}:
            raise ValueError("Invalid format. Choose 'decimal', 'binary', or 'hex'.")
        cls._display_format = display_format

    def as_bin(self):
        """ Returns the number in binary form """
        return f"{self.number:08b}"
    
    def as_hex(self):
        """ Returns the number in hexadecimal form """
        return f"{self.number:02X}"

    def __add__(self, other):
        if isinstance(other, FiniteNumber) and self.FiniteField == other.FiniteField:
            result = self.FiniteField.suma(self.number, other.number)
            return FiniteNumber(result, self.FiniteField)
        raise ValueError("Both numbers must be from the same finite field")

    def __sub__(self, other):
        # Subtraction is equivalent to addition in the field
        return self + other

    def __mul__(self, other):
        if isinstance(other, FiniteNumber) and self.FiniteField == other.FiniteField:
            result = self.FiniteField.producto(self.number, other.number)
            return FiniteNumber(result, self.FiniteField)
        raise ValueError("Both numbers must be from the same finite field")

    def __truediv__(self, other):
        if isinstance(other, FiniteNumber) and self.FiniteField == other.FiniteField:
            if other.number == 0:
                raise ZeroDivisionError("Division by zero is not defined in a finite field")
            
            # Find the multiplicative inverse of the divisor
            inverse_other = self.FiniteField.inverso(other.number)
            
            # Multiply the dividend by the inverse
            result = self.FiniteField.producto(self.number, inverse_other)
            return FiniteNumber(result, self.FiniteField)
        
        raise ValueError("Both numbers must be from the same finite field")

    def __eq__(self, other):
        return isinstance(other, FiniteNumber) and self.number == other.number and self.FiniteField == other.FiniteField

    def __str__(self):
        if FiniteNumber._display_format == "decimal":
            return str(self.number)
        elif FiniteNumber._display_format == "binary":
            return self.as_bin()
        elif FiniteNumber._display_format == "hex":
            return self.as_hex()

    def __repr__(self):
        return f"FiniteNumber({self.number}, FiniteField)"

    def inverse(self):
        """Finds the multiplicative inverse of the number in the finite field. """
        result = self.FiniteField.inverso(self.number)
        return FiniteNumber(result, self.FiniteField)