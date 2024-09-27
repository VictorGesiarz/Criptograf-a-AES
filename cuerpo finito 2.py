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
        self.table_exp = [0] * 512  # 2 * 255 to handle overflow cases
        self.table_log = [0] * 256
        self._crear_tablas()
    

    def _crear_tablas(self) -> None:
        """
        Creates the EXP and LOG tables for efficient calculations in the Galois field.
        """
		

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
        pass


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


# Test the class
P = G_F()
n1 = 5
n2 = 254

print(f'The two numbers we have are: {n1} and {n2}')
sum_result = P.suma(n1, n2)
print(f'The result of their sum is: {sum_result}')
product_result = P.producto(n1, n2)
print(f'The result of their product is: {product_result}')
inverse_n1 = P.inverso(n1)
print(f'The inverse of {n1} in the field is: {inverse_n1}')
inverse_n2 = P.inverso(n2)
print(f'The inverse of {n2} in the field is: {inverse_n2}')
