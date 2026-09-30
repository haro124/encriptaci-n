"""
CONSTRUYE TU PROPIA CLAVE RSA  (opción 6 del menú)
==================================================
Aquí eliges TÚ los números y el programa enseña, división por división,
todo lo que pasa por dentro:

    1. Eliges p y q          -> se comprueba que sean primos de verdad
    2. n = p·q  y  φ(n)      -> con la multiplicación a la vista
    3. Eliges e              -> tabla de Euclides para ver si mcd(e, φ) = 1
    4. d = e⁻¹ mod φ(n)      -> Euclides extendido con Bézout, paso a paso
    5. Ciframos y desciframos con TUS números
    6. Firmamos y verificamos, y se ve cómo la firma se cae al tocar el texto

El ejemplo por defecto (61, 53, 17) es el clásico de los libros: da
n = 3233, φ = 3120 y d = 2753. Pulsa Enter para aceptarlo.

Uso:
    python3 mi_clave.py            # te pregunta todo
    python3 mi_clave.py 61 53 17   # p, q y e ya dados
"""

import sys
from math import gcd

from formula import (mcd_explicado, inverso_explicado, cifrar_explicado,
                     descifrar_explicado, corto, verde, rojo, amarillo,
                     cian, gris, negrita)
from rsa_core import es_primo, _tam_bloque, hash_mensaje

P_SUGERIDO, Q_SUGERIDO = 61, 53
# Orden de preferencia para sugerir e: el estándar real primero, luego los
# pequeños que se ven bien en el pizarrón.
CANDIDATOS_E = (65537, 17, 3, 5, 7, 11, 13, 19, 23, 29)


def titulo(texto):
    print("\n" + "=" * 64)
    print(negrita(texto))
    print("=" * 64)


def _pedir(mensaje, defecto):
    """input() con valor por defecto: Enter acepta el sugerido."""
    bruto = input(f"{mensaje} [{defecto}]: ").strip()
    return defecto if not bruto else bruto


def _entero(bruto):
    """Convierte a int o devuelve None si no es un entero."""
    try:
        return int(bruto)
    except (TypeError, ValueError):
        return None


def pedir_primo(nombre, defecto, distinto_de=None, ya_dado=None):
    """Pide un primo y no sigue hasta que lo sea. ya_dado salta la pregunta."""
    while True:
        valor = _entero(ya_dado if ya_dado is not None
                        else _pedir(f"Elige {nombre} (un número PRIMO)", defecto))
        ya_dado = None
        if valor is None:
            print(rojo("  Eso no es un número entero."))
            continue
        if valor < 2:
            print(rojo("  Tiene que ser 2 o mayor."))
            continue
        if not es_primo(valor):
            print(rojo(f"  {valor} NO es primo: Miller-Rabin lo descarta."))
            print(gris("  RSA necesita primos. Si n tuviera más de dos factores,"))
            print(gris("  φ(n) no sería (p-1)(q-1) y la clave no funcionaría."))
            continue
        if distinto_de is not None and valor == distinto_de:
            print(rojo(f"  p y q tienen que ser DISTINTOS."))
            print(gris("  Si p = q, entonces n = p² y sacar p es una raíz cuadrada."))
            continue
        print(verde(f"  {valor} es primo ✔"))
        return valor


def sugerir_e(phi):
    """Primer e razonable que sea menor que φ(n) y coprimo con él."""
    for candidato in CANDIDATOS_E:
        if 1 < candidato < phi and gcd(candidato, phi) == 1:
            return candidato
    return None


def pedir_e(phi, ya_dado=None):
    """Pide e y enseña la tabla de Euclides para aceptarlo o rechazarlo."""
    defecto = sugerir_e(phi)
    while True:
        valor = _entero(ya_dado if ya_dado is not None
                        else _pedir("Elige e (el exponente público)", defecto))
        ya_dado = None
        if valor is None:
            print(rojo("  Eso no es un número entero."))
            continue
        if not 1 < valor < phi:
            print(rojo(f"  e tiene que estar entre 2 y φ(n)-1 = {phi - 1}."))
            continue
        if mcd_explicado(valor, phi) != 1:
            print(rojo(f"  mcd({valor}, {phi}) ≠ 1: NO son coprimos, así que e no"))
            print(rojo("  tiene inverso módulo φ(n) y no existiría d. Elige otro."))
            continue
        print(verde(f"  mcd({valor}, {phi}) = 1  ->  son coprimos ✔  e sirve."))
        return valor


def cifrar_con_texto(texto, publica, privada):
    """Camino normal: la clave es grande y cabe texto en los bloques."""
    cifrado = cifrar_explicado(texto, publica)
    print()
    recuperado = descifrar_explicado(cifrado, privada)
    print(verde(f"\n  Recuperado: {recuperado!r}")
          if recuperado == texto else rojo("\n  ✗ No coincide."))
    return texto


def cifrar_con_numero(n, e, d):
    """
    Camino de clave pequeña: no cabe ni un byte de texto, así que ciframos
    un número suelto. Es exactamente la misma fórmula.
    """
    print(amarillo(f"  Tu n = {n} ({n.bit_length()} bits) es pequeño: no cabe ni un"))
    print(amarillo("  byte de texto en un bloque. Hacen falta 17 bits como mínimo"))
    print(amarillo("  (p y q de 3 cifras, p.ej. 257 y 263). Ciframos un NÚMERO."))
    while True:
        m = _entero(_pedir(f"\n  Elige un número m menor que {n}", min(42, n - 1)))
        if m is None or not 0 <= m < n:
            print(rojo(f"  Tiene que ser un entero entre 0 y {n - 1}."))
            continue
        break

    c = pow(m, e, n)
    recuperado = pow(c, d, n)
    print(amarillo("\n  ── CIFRADO  c = m^e mod n ──"))
    print(f"    c = {m}^{e} mod {n} = {cian(c)}")
    print(amarillo("  ── DESCIFRADO  m = c^d mod n ──"))
    print(f"    m = {c}^{d} mod {n} = {recuperado}")
    print(verde(f"    Volvió a salir {m} ✔") if recuperado == m
          else rojo("    ✗ No coincide."))
    return str(m)


def firmar_y_verificar(mensaje, e, d, n):
    """Firma el mensaje y demuestra que cambiarlo invalida la firma."""
    h = hash_mensaje(mensaje, n)
    s = pow(h, d, n)
    print(gris(f"  Mensaje que se firma: {mensaje!r}"))
    print(f"  h  = SHA-256(texto) mod n = {corto(h)}")
    print(f"  s  = h^d mod n            = {cian(corto(s))}")
    print(gris("  Esa s solo la puede calcular quien tenga d."))

    h_verificado = pow(s, e, n)
    print(f"\n  h' = s^e mod n            = {corto(h_verificado)}")
    if h_verificado == h:
        print(verde("  ✔ h' == h: la firma es válida."))
    else:
        print(rojo("  ✗ h' != h: firma inválida."))

    alterado = mensaje + "!"
    h_alterado = hash_mensaje(alterado, n)
    print(gris(f"\n  Ahora cambiamos el mensaje a {alterado!r} sin tocar la firma:"))
    print(f"  SHA-256 del texto alterado mod n = {corto(h_alterado)}")
    if h_alterado != h_verificado:
        print(verde("  ✔ Ya no cuadra con h': la firma detecta el cambio."))
    else:
        print(amarillo("  Coincidieron por azar: con un n tan pequeño puede pasar."))


def main():
    args = sys.argv[1:]
    p_arg = args[0] if len(args) > 0 else None
    q_arg = args[1] if len(args) > 1 else None
    e_arg = args[2] if len(args) > 2 else None

    titulo("CONSTRUYE TU PROPIA CLAVE RSA")
    print("Tú eliges los números; aquí se ve toda la matemática por dentro.")
    print(gris("Pulsa Enter para aceptar el valor sugerido entre corchetes."))

    titulo("PASO 1 · ELIGE TUS DOS PRIMOS  p  y  q")
    p = pedir_primo("p", P_SUGERIDO, ya_dado=p_arg)
    q = pedir_primo("q", Q_SUGERIDO, distinto_de=p, ya_dado=q_arg)

    titulo("PASO 2 · EL MÓDULO n Y LA FUNCIÓN φ(n)")
    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"  n    = p × q         = {p} × {q} = {negrita(n)}   [{n.bit_length()} bits]")
    print(f"  φ(n) = (p-1) × (q-1) = {p - 1} × {q - 1} = {negrita(phi)}")
    print(gris("\n  n es público: viaja por la red. φ(n) es el secreto de verdad,"))
    print(gris("  porque para calcularlo hay que conocer p y q."))
    if phi < 3:
        print(rojo("\n  φ(n) es demasiado pequeño para elegir un e válido."))
        print(rojo("  Vuelve a ejecutar con primos más grandes (5, 7, 11...)."))
        return

    titulo("PASO 3 · ELIGE e  (tiene que ser COPRIMO con φ(n))")
    e = pedir_e(phi, ya_dado=e_arg)

    titulo("PASO 4 · CALCULA d = e⁻¹ mod φ(n)")
    d = inverso_explicado(e, phi)
    if d is None:
        return
    producto = e * d
    print(f"\n  Comprobación: e × d = {e} × {d} = {producto}")
    print(f"                {producto} mod {phi} = {producto % phi}")
    print(verde("  ✔ Da 1, así que d es el inverso correcto.")
          if producto % phi == 1 else rojo("  ✗ No da 1."))

    titulo("PASO 5 · TUS CLAVES")
    print(negrita("  Clave PÚBLICA  (e, n) = ") + f"({e}, {n})")
    print(gris("    se la das a cualquiera; con ella te cifran y verifican tu firma"))
    print(negrita("  Clave PRIVADA  (d, n) = ") + f"({d}, {n})")
    print(gris("    no sale de tu máquina; con ella descifras y firmas"))

    titulo("PASO 6 · CIFRA Y DESCIFRA CON TUS NÚMEROS")
    if _tam_bloque(n) >= 1:
        texto = _pedir("  Escribe el mensaje", "Hola RSA")
        print()
        firmado = cifrar_con_texto(texto, (e, n), (d, n))
    else:
        firmado = cifrar_con_numero(n, e, d)

    titulo("PASO 7 · FIRMA DIGITAL  (RSA al revés)")
    firmar_y_verificar(firmado, e, d, n)

    titulo("FIN")
    print("Todo salió de dos primos que elegiste tú. La seguridad está en que")
    print("de n nadie pueda volver a sacar p y q: por eso en la vida real")
    print("tienen 1024 bits cada uno y no dos cifras.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nSaliendo.")
