from cuerpo_finito import G_F, FiniteNumber
    
# Test the class with the previously defined G_F class
finite_field = G_F()

a = FiniteNumber(5, finite_field)
b = FiniteNumber(3, finite_field)
print(f'The numbers are: {a} and {b}')
FiniteNumber.set_format('binary')
print(f'The numbers are: {a} and {b}')
FiniteNumber.set_format('hex')
print(f'The numbers are: {a} and {b}')
FiniteNumber.set_format('decimal')

# Addition in the finite field
sum_result = a + b
print(f"{a} + {b} in the field = {sum_result}")

# Multiplication in the finite field
product_result = a * b
print(f"{a} * {b} in the field = {product_result}")

division_result = a / b
print(f"{a} / {b} in the field = {division_result}")

# Inverse in the finite field
inverse_a = a.inverse()
print(f"Inverse of {a} in the field = {inverse_a}")
