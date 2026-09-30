"""
Presentación de la FÓRMULA RSA paso a paso, para la exposición.

Cifra y descifra exactamente igual que rsa_core.cifrar_mensaje /
descifrar_mensaje, pero imprimiendo cada paso para que los estudiantes
vean la matemática en tiempo real:

    texto -> bytes -> número m -> c = m^e mod n        (cifrado)
    c -> m = c^d mod n -> bytes -> texto               (descifrado)

También muestra la FIRMA digital, que usa RSA al revés:

    h = SHA-256(texto) -> s = h^d mod n                (firmar, clave privada)
    s -> h' = s^e mod n -> ¿h' == h?                   (verificar, clave pública)
"""

import os
import sys

from rsa_core import _tam_bloque, hash_mensaje

# Windows: activa colores ANSI y evita que un emoji o acento tumbe el
# programa en consolas que no usan UTF-8 (en Linux no hace nada).
if os.name == "nt":
    os.system("")
for _flujo in (sys.stdout, sys.stderr):
    try:
        _flujo.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(codigo, texto):
    return f"\033[{codigo}m{texto}\033[0m" if _COLOR else str(texto)


def verde(t):    return _c("92", t)
def rojo(t):     return _c("91", t)
def amarillo(t): return _c("93", t)
def cian(t):     return _c("96", t)
def gris(t):     return _c("90", t)
def negrita(t):  return _c("1", t)


def corto(numero, ancho=24):
    """Abrevia un número gigante: 123456…789012 (309 dígitos)."""
    s = str(numero)
    if len(s) <= 2 * ancho:
        return s
    return f"{s[:ancho]}…{s[-ancho:]} ({len(s)} dígitos)"


def mostrar_clave(nombre, publica, privada=None):
    e, n = publica
    print(negrita(f"Clave pública de {nombre}:"))
    print(f"  e = {e}")
    print(f"  n = {corto(n)}  [{n.bit_length()} bits]")
    if privada:
        print(gris(f"  d = {corto(privada[0])}  (PRIVADA, nunca sale de aquí)"))


def cifrar_explicado(texto, publica):
    """Cifra 'texto' mostrando la fórmula bloque a bloque. Devuelve la lista de enteros."""
    e, n = publica
    tam = _tam_bloque(n)
    datos = texto.encode("utf-8")
    cifrados = []

    print(amarillo(f"── CIFRANDO  c = m^e mod n   (e = {e}) ──"))
    for i in range(0, len(datos), tam):
        trozo = datos[i:i + tam]
        bloque = b"\x01" + trozo
        m = int.from_bytes(bloque, "big")
        c = pow(m, e, n)
        cifrados.append(c)
        print(f"  bloque {i // tam}: {trozo.decode('utf-8', 'replace')!r}")
        print(gris(f"    bytes  = {bloque.hex(' ')}"))
        print(f"    m      = {corto(m)}")
        print(f"    c = m^{e} mod n = {cian(corto(c))}")
    return cifrados


def descifrar_explicado(cifrados, privada):
    """Descifra mostrando la fórmula bloque a bloque. Devuelve el texto."""
    d, n = privada
    salida = bytearray()

    print(amarillo("── DESCIFRANDO  m = c^d mod n   (solo quien tiene d) ──"))
    for i, c in enumerate(cifrados):
        m = pow(c, d, n)
        bloque = m.to_bytes((m.bit_length() + 7) // 8, "big")
        salida.extend(bloque[1:])
        print(f"  bloque {i}: c = {cian(corto(c))}")
        print(f"    m = c^d mod n = {corto(m)}")
        print(gris(f"    bytes = {bloque.hex(' ')}"))
    return salida.decode("utf-8")


def firmar_explicado(texto, privada, nombre):
    """Firma 'texto' mostrando la fórmula. Devuelve el entero de la firma."""
    d, n = privada
    h = hash_mensaje(texto, n)
    s = pow(h, d, n)

    print(amarillo(f"── FIRMANDO  s = h^d mod n   (con la clave PRIVADA de {nombre}) ──"))
    print(f"  h = SHA-256(texto) mod n = {corto(h)}")
    print(f"  s = h^d mod n            = {cian(corto(s))}")
    print(gris("    Nadie más puede calcular esta s: hace falta d."))
    return s


def verificar_explicado(texto, firma, publica, nombre):
    """Verifica la firma mostrando la fórmula. Devuelve True/False."""
    e, n = publica
    if firma is None:
        print(rojo(f"⚠  El mensaje llegó SIN FIRMA: no puedo probar que sea de {nombre}."))
        return False

    h_esperado = hash_mensaje(texto, n)
    h_recuperado = pow(firma, e, n)
    valida = h_recuperado == h_esperado

    print(amarillo(f"── VERIFICANDO FIRMA  h' = s^e mod n   (clave PÚBLICA de {nombre}) ──"))
    print(f"  s                        = {corto(firma)}")
    print(f"  h' = s^e mod n           = {corto(h_recuperado)}")
    print(f"  SHA-256(texto) mod n     = {corto(h_esperado)}")
    if valida:
        print(verde(f"  ✔ FIRMA VÁLIDA: el mensaje es de {nombre} y nadie lo alteró."))
    else:
        print(rojo(f"  ✗ FIRMA INVÁLIDA: esto NO lo escribió {nombre}, "
                   "o el texto fue modificado en el camino."))
    return valida
