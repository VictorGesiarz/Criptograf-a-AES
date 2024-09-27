
class G_F:
	"""
	Genera un cuerpo finito usando como polinomio irreducible el dado
	representado como un entero. Por defecto toma el polinomio del AES.
	Los elementos del cuerpo los representaremos por enteros 0<= n <= 255.
	"""

	def __init__(self, polinomio_irreducible = 0x11B) -> None:
		"""
		Entrada: un entero que representa el polinomio para construir el cuerpo
		Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posición
		i-ésima tenga valor a=g**i y la segunda tal que en la posición a-ésima
		tenga el valor i tal que a=g**i. (g generador del cuerpo finito
		representado por el menor entero entre 0 y 255.)
		"""
		self.polinomio_irreducible = polinomio_irreducible
		self.table_exp = None
		self.table_log = None


	def _creaet_tables(self) -> int:
		pass


	def _find_generator(self) -> int:
		pass


	def suma(self, a, b) -> bin:
		"""
		Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
		Salida: un elemento del cuerpo representado por un entero entre 0 y 255
		que es la suma módulo 2 entre los dos polinomios. 
		"""
		return a ^ b 


	def xTimes(self, n): 
		"""
		Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
		Salida: un elemento del cuerpo representado por un entero entre 0 y 255
		que es el producto en el cuerpo de 'n' y 0x02 (el polinomio X).
		"""
		result = n << 1
		if result >= 256: 
			return self.suma(result, self.polinomio_irreducible) 
		return result


	def producto(self, a, b):
		"""
		Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
		Salida: un elemento del cuerpo representado por un entero entre 0 y 255
		que es el producto en el cuerpo de la entrada.
		Atención: Se valorará la eficiencia. No es lo mismo calcularlo
		usando la definición en términos de polinomios o calcular
		usando las tablas Tabla_EXP y Tabla_LOG.
		"""


	def inverso(self, n):
		"""
		Entrada: un elementos del cuerpo representado por un entero entre 0 y 255
		Salida: 0 si la entrada es 0,
		el inverso multiplicativo de n representado por un entero entre
		1 y 255 si n <> 0.
		Atención: Se valorará la eficiencia.
		"""


P = G_F()
n1 = 5
n2 = 254

print(f'Los dos números que tenemos son: {n1} y {n2}')
resultado = P.xTimes(n2)
print(f'El resultado de sumarlos es: {resultado}')