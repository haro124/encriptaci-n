"""
Núcleo criptográfico RSA — basado en MCD y coprimalidad.

Todo implementado desde cero, sin librerías externas:
  - Euclides extendido        -> mcd + coeficientes de Bézout
  - Inverso modular           -> existe solo si mcd(a, n) = 1
  - Miller-Rabin              -> test de primalidad
  - Generación de claves RSA
  - Cifrado / descifrado por bloques (texto de cualquier longitud)
  - Firma digital             -> autenticidad: ¿quién escribió esto?

Referencia: los pasos siguen el documento "MCD y Coprimalidad en Criptografía".
"""

import hashlib
import secrets
from math import gcd


# ---------------------------------------------------------------------------
# 1. MCD y coprimalidad (algoritmo de Euclides extendido)
# ---------------------------------------------------------------------------
def euclides_extendido(a, b):
    """Devuelve (g, x, y) tal que a*x + b*y = g = mcd(a, b) (identidad de Bézout)."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = euclides_extendido(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def son_coprimos(a, b):
    """True si mcd(a, b) == 1."""
    return gcd(a, b) == 1


def inverso_modular(a, n):
    """
    Inverso modular de a módulo n: x tal que a*x ≡ 1 (mod n).
    Solo existe si a y n son coprimos (teorema central del documento).
    """
    g, x, _ = euclides_extendido(a, n)
    if g != 1:
        raise ValueError(f"No existe inverso: mcd({a}, {n}) = {g} ≠ 1")
    return x % n


# ---------------------------------------------------------------------------
# 2. Primalidad y generación de primos (Miller-Rabin)
# ---------------------------------------------------------------------------
_PRIMOS_PEQUENOS = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def es_primo(n, rondas=40):
    """Test de primalidad probabilístico Miller-Rabin."""
    if n < 2:
        return False
    for p in _PRIMOS_PEQUENOS:
        if n % p == 0:
            return n == p

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rondas):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generar_primo(bits):
    """Genera un primo aleatorio del número de bits pedido."""
    while True:
        # bit alto en 1 (asegura tamaño) y bit bajo en 1 (impar)
        candidato = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if es_primo(candidato):
            return candidato


# ---------------------------------------------------------------------------
# 3. Generación de claves RSA
# ---------------------------------------------------------------------------
def generar_claves(bits=1024, e=65537, verboso=False):
    """
    Genera un par de claves RSA.
    'bits' es el tamaño de CADA primo, así que el módulo n tendrá ~2*bits.

    Devuelve: (clave_publica, clave_privada, (p, q))
      clave_publica  = (e, n)
      clave_privada  = (d, n)
    """
    while True:
        p = generar_primo(bits)
        q = generar_primo(bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)          # φ(n) = (p-1)(q-1)
        if gcd(e, phi) == 1:             # e debe ser coprimo con φ(n)
            d = inverso_modular(e, phi)  # d = e^-1 mod φ(n)  (Euclides extendido)
            if verboso:
                print(f"  p      = {p}")
                print(f"  q      = {q}")
                print(f"  n      = {n}   ({n.bit_length()} bits)")
                print(f"  φ(n)   = {phi}")
                print(f"  e      = {e}   (mcd(e, φ)=1 -> coprimos ✔)")
                print(f"  d      = {d}   (e^-1 mod φ(n))")
            return (e, n), (d, n), (p, q)


# ---------------------------------------------------------------------------
# 4. Cifrado y descifrado de texto (por bloques, cualquier longitud)
# ---------------------------------------------------------------------------
def _tam_bloque(n):
    """Bytes de texto que caben con seguridad en un bloque para el módulo n."""
    return (n.bit_length() - 1) // 8 - 1


def cifrar_mensaje(texto, clave_publica):
    """Cifra un string. Devuelve una lista de enteros (un entero por bloque)."""
    e, n = clave_publica
    tam = _tam_bloque(n)
    if tam < 1:
        raise ValueError("La clave es demasiado pequeña para cifrar texto.")
    datos = texto.encode("utf-8")
    cifrados = []
    for i in range(0, len(datos), tam):
        # marcador 0x01 al frente para no perder bytes cero al convertir a entero
        bloque = b"\x01" + datos[i:i + tam]
        m = int.from_bytes(bloque, "big")
        cifrados.append(pow(m, e, n))        # c = m^e mod n
    return cifrados


def descifrar_mensaje(cifrados, clave_privada):
    """Descifra la lista de enteros y devuelve el string original."""
    d, n = clave_privada
    salida = bytearray()
    for c in cifrados:
        m = pow(c, d, n)                     # m = c^d mod n
        bloque = m.to_bytes((m.bit_length() + 7) // 8, "big")
        salida.extend(bloque[1:])            # quita el marcador 0x01
    return salida.decode("utf-8")


# ---------------------------------------------------------------------------
# 5. Firma digital (¿quién escribió el mensaje?)
# ---------------------------------------------------------------------------
# El cifrado da CONFIDENCIALIDAD (nadie más lo lee) pero no AUTENTICIDAD:
# la clave pública de Ana la tiene cualquiera, así que cualquiera puede
# escribirle diciendo "soy Beto". La firma resuelve eso usando RSA al revés:
#
#     firmar     : s = h^d mod n   -> con la clave PRIVADA del que firma
#     verificar  : h = s^e mod n   -> con la clave PÚBLICA del que firmó
#
# Solo el dueño de d puede producir una s válida, y como h es el resumen
# del texto, cambiar una sola letra del mensaje invalida la firma.
# ---------------------------------------------------------------------------
def hash_mensaje(texto, n):
    """
    Resumen SHA-256 del texto, como número y reducido mod n.
    El 'mod n' hace falta porque la firma vive en Z_n: si el resumen fuera
    mayor que n, la exponenciación modular ya no podría recuperarlo.
    """
    resumen = hashlib.sha256(texto.encode("utf-8")).digest()
    return int.from_bytes(resumen, "big") % n


def firmar(texto, clave_privada):
    """Firma el texto: s = h^d mod n (solo quien tiene d puede calcularla)."""
    d, n = clave_privada
    return pow(hash_mensaje(texto, n), d, n)


def verificar(texto, firma, clave_publica):
    """True si 'firma' fue hecha por el dueño de 'clave_publica' sobre 'texto'."""
    e, n = clave_publica
    return pow(firma, e, n) == hash_mensaje(texto, n)


# ---------------------------------------------------------------------------
# Prueba rápida al ejecutar este archivo directamente
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generando claves de prueba (512 bits por primo)...")
    pub, priv, _ = generar_claves(bits=512, verboso=True)
    mensaje = "Coprimalidad = seguridad 🔐"
    c = cifrar_mensaje(mensaje, pub)
    m = descifrar_mensaje(c, priv)
    print(f"\nOriginal   : {mensaje!r}")
    print(f"Descifrado : {m!r}")
    print("OK ✔" if m == mensaje else "FALLO ✗")

    print("\nFirma digital:")
    s = firmar(mensaje, priv)
    print(f"  s = {str(s)[:60]}...")
    print("  verifica con la pública      :",
          "OK ✔" if verificar(mensaje, s, pub) else "FALLO ✗")
    print("  con el texto alterado        :",
          "rechazada ✔" if not verificar(mensaje + "!", s, pub) else "ACEPTADA ✗")
