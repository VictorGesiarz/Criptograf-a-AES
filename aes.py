
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
		self.SBox = []
		self.InvSBox = []
		self.Rcon = None
		self.InvMixMatrix = []