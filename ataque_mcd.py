"""
ATAQUE DE MCD A RSA  (batch GCD)
================================
Reproduce el ataque real descrito en el documento (sección 6):

    n1 = p · q1
    n2 = p · q2     ->     mcd(n1, n2) = p     ->     ¡ambas claves rotas!

Si dos claves comparten un primo por mala aleatoriedad, un simple MCD
revela ese primo SIN necesidad de factorizar. Fue el fallo real de 2012
(Heninger et al. / Lenstra et al.) que rompió miles de claves TLS y SSH.

Este script:
  1. Simula un atacante que capturó varios módulos públicos.
  2. Ejecuta batch GCD entre todos los pares.
  3. Recupera las claves privadas de las que comparten primo.
  4. Demuestra que las claves con buena aleatoriedad RESISTEN.

Uso:
    python3 ataque_mcd.py            # bits pequeños para imprimir rápido
    python3 ataque_mcd.py 512        # primos más grandes
"""

import sys
from math import gcd

from rsa_core import generar_primo, inverso_modular

E = 65537


def generar_escenario(bits):
    """
    Crea 4 módulos públicos:
      - n1 y n2 comparten un primo 'p' (VULNERABLES, mala aleatoriedad)
      - n3 y n4 usan primos únicos      (SEGUROS)
    """
    p = generar_primo(bits)          # primo repetido por accidente
    q1 = generar_primo(bits)
    q2 = generar_primo(bits)
    n1 = p * q1
    n2 = p * q2

    a, b, c, d = (generar_primo(bits) for _ in range(4))
    n3 = a * b
    n4 = c * d

    return {"clave_A": n1, "clave_B": n2, "clave_C": n3, "clave_D": n4}


def batch_gcd(modulos):
    """Compara cada par de módulos. Devuelve los pares con mcd > 1."""
    rotas = []
    nombres = list(modulos)
    for i in range(len(nombres)):
        for j in range(i + 1, len(nombres)):
            na, nb = modulos[nombres[i]], modulos[nombres[j]]
            factor = gcd(na, nb)
            if factor > 1:
                rotas.append((nombres[i], nombres[j], factor))
    return rotas


def romper_clave(nombre, n, p):
    """Con el primo p conocido, recupera q, φ y la clave privada d. Verifica."""
    q = n // p
    phi = (p - 1) * (q - 1)
    d = inverso_modular(E, phi)

    # verificación: ciframos y desciframos un número de prueba
    prueba = 12345
    c = pow(prueba, E, n)
    recuperado = pow(c, d, n)
    ok = "✔" if recuperado == prueba else "✗"

    print(f"    -> {nombre} ROTA:")
    print(f"       p = {p}")
    print(f"       q = {q}")
    print(f"       d (clave privada) = {str(d)[:70]}...")
    print(f"       prueba de descifrado: {prueba} -> ... -> {recuperado}  {ok}")


def main():
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 256

    print("=" * 64)
    print("SIMULACIÓN DE ATAQUE DE MCD A RSA")
    print("=" * 64)

    modulos = generar_escenario(bits)

    print("\n[1] Módulos públicos capturados por el atacante:")
    print("    (esto es información PÚBLICA, cualquiera la puede ver)\n")
    for nombre, n in modulos.items():
        print(f"    {nombre}: {str(n)[:64]}...")

    print("\n[2] Ejecutando batch GCD entre todos los pares...\n")
    rotas = batch_gcd(modulos)

    if not rotas:
        print("    Ningún par comparte factores. Todas las claves resisten. 🛡️")
        return

    for a, b, factor in rotas:
        print(f"    ⚠  {a} y {b} comparten un primo -> mcd = {str(factor)[:40]}...\n")
        romper_clave(a, modulos[a], factor)
        print()
        romper_clave(b, modulos[b], factor)

    print("\n[3] Resultado:")
    seguras = [n for n in modulos if not any(n in (a, b) for a, b, _ in rotas)]
    print(f"    Claves ROTAS por MCD : {sorted({x for a, b, _ in rotas for x in (a, b)})}")
    print(f"    Claves que RESISTEN  : {seguras}")
    print("\n    Moraleja: la matemática de RSA es correcta. El fallo estuvo en")
    print("    la ALEATORIEDAD. Primos únicos y bien aleatorios = seguridad.")


if __name__ == "__main__":
    main()
