"""
DEMO TODO-EN-UNO (sin red)
==========================
Ideal para la exposición: corre en una sola terminal y muestra, paso a
paso, todo el ciclo del documento:

    1. Generación de claves (con el MCD y la coprimalidad a la vista)
    2. Cifrado de un mensaje
    3. Descifrado
    4. Ataque de MCD sobre claves mal generadas

Uso:
    python3 demo_local.py
    python3 demo_local.py "Mi mensaje secreto"
"""

import sys

from rsa_core import generar_claves, cifrar_mensaje, descifrar_mensaje
from ataque_mcd import generar_escenario, batch_gcd, romper_clave


def titulo(texto):
    print("\n" + "=" * 64)
    print(texto)
    print("=" * 64)


def main():
    mensaje = sys.argv[1] if len(sys.argv) > 1 else "El MCD es la base de RSA 🔐"

    titulo("PASO 1 · GENERACIÓN DE CLAVES RSA")
    print("e debe ser COPRIMO con φ(n)  ->  mcd(e, φ(n)) = 1\n")
    publica, privada, (p, q) = generar_claves(bits=512, verboso=True)

    titulo("PASO 2 · CIFRADO  (c = m^e mod n)")
    print(f"Mensaje original: {mensaje!r}\n")
    cifrado = cifrar_mensaje(mensaje, publica)
    for i, c in enumerate(cifrado):
        print(f"  bloque {i}: {str(c)[:66]}...")

    titulo("PASO 3 · DESCIFRADO  (m = c^d mod n)")
    recuperado = descifrar_mensaje(cifrado, privada)
    print(f"Mensaje recuperado: {recuperado!r}")
    print("Coinciden ✔" if recuperado == mensaje else "NO coinciden ✗")

    titulo("PASO 4 · ATAQUE DE MCD  (batch GCD)")
    print("Dos claves comparten un primo por mala aleatoriedad...\n")
    modulos = generar_escenario(bits=256)
    for nombre, n in modulos.items():
        print(f"  {nombre}: {str(n)[:56]}...")
    print()
    rotas = batch_gcd(modulos)
    for a, b, factor in rotas:
        print(f"⚠  {a} y {b} comparten primo -> mcd revela p\n")
        romper_clave(a, modulos[a], factor)
        print()
        romper_clave(b, modulos[b], factor)

    titulo("FIN")
    print("La coprimalidad hace posible descifrar; la mala aleatoriedad")
    print("permite el ataque. Mismo MCD que construye y que rompe RSA.")


if __name__ == "__main__":
    main()
