"""
ESPÍA / ATACANTE EN MEDIO (man-in-the-middle pasivo)
====================================================
Se coloca entre los dos peers y reenvía todo el tráfico sin modificarlo,
así que los peers no notan nada. Muestra lo que ve un atacante en la red:

  1. Las claves públicas (e, n)      -> sí las ve, son públicas.
  2. Los mensajes cifrados (c)       -> sí los ve... pero son solo números.
  3. Intenta leer c como texto       -> basura.
  4. Intenta ROMPER la clave         -> factorizar n con Pollard rho.
       · clave de 1024 bits: se rinde, no puede.  🛡️
       · clave débil (--bits 32):  la rompe y lee todo.  💀
  5. Ve la firma s de cada mensaje   -> sí la ve, pero no la puede falsificar.
  6. Calcula cuánto tardaría con una clave real de 2048 bits (--estimar).

Esquema en una sola PC:

    Efrén (peer)  --->  espía :6000  --->  Harold (peer) :5000

Uso:
    python3 espia.py                          # escucha 6000, reenvía a 127.0.0.1:5000
    python3 espia.py 6000 127.0.0.1 5000 --tiempo 20
    python3 espia.py --estimar 4096           # estimación para otro tamaño de clave
    python3 espia.py --estimar 0              # sin estimación

Luego Harold:   python3 peer.py escuchar 5000 --nombre Harold
y Efrén:      python3 peer.py conectar 127.0.0.1 6000 --nombre Efrén
"""

import argparse
import json
import math
import random
import socket
import struct
import threading
import time

from formula import corto, rojo, verde, amarillo, cian, gris, negrita
from red import _recibir_exacto, escuchar_una_conexion, conectar_con_reintentos
from rsa_core import inverso_modular

claves_rotas = {}          # nombre del dueño de la clave -> (d, n)
claves_vistas = {}         # nombre -> (e, n)
imprimir = threading.Lock()


# ---------------------------------------------------------------------------
# ¿CUÁNTO TARDARÍA EN ROMPER UNA CLAVE DE VERDAD (2048 bits)?
# ---------------------------------------------------------------------------
# Dos cuentas distintas, las dos en log10 porque los números no caben en la
# pantalla (ni en un float si no se tiene cuidado):
#
#   · Pollard rho  : lo que uso yo aquí. Encuentra un factor p en ~sqrt(p)
#                    pasos, y p ≈ sqrt(n), así que ~2^(bits/4) pasos. La
#                    velocidad se MIDE en esta máquina, no se inventa.
#   · GNFS         : el mejor algoritmo conocido, subexponencial:
#                    exp( (64/9)^(1/3) · (ln n)^(1/3) · (ln ln n)^(2/3) ).
#                    Se calibra con un récord real para que el número
#                    signifique algo.
# ---------------------------------------------------------------------------
SEGUNDOS_POR_ANIO = 31_557_600
EDAD_UNIVERSO = 1.38e10            # años
# Récord real: RSA-250 (829 bits) factorizado en 2020 con ~2700 años-CPU
# (Boudot, Gaudry, Guillevic, Heninger, Thomé, Zimmermann).
BITS_RECORD = 829
ANIOS_CPU_RECORD = 2700
NUCLEOS_GRANJA = 1_000_000         # "¿y si tuviera un millón de núcleos?"


def _log10_ops_gnfs(bits):
    """log10 de las operaciones que necesita GNFS para un n de 'bits' bits."""
    ln_n = bits * math.log(2)
    ln_ops = (64 / 9) ** (1 / 3) * ln_n ** (1 / 3) * math.log(ln_n) ** (2 / 3)
    return ln_ops / math.log(10)


def _velocidad_rho(bits, muestras=20_000):
    """Mide cuántos pasos de Pollard rho hace ESTA máquina por segundo."""
    n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
    y, c = random.randrange(1, n), 1
    t0 = time.perf_counter()
    for _ in range(muestras):
        y = (y * y + c) % n            # el paso caro: una multiplicación mod n
    dt = time.perf_counter() - t0
    return muestras / dt if dt > 0 else float("inf")


def _diez(log10_valor, decimales=1):
    """Formatea un log10 como '6.8 × 10^14' (o el número normal si es pequeño)."""
    if log10_valor < 5:
        return f"{10 ** log10_valor:,.0f}"
    exponente = math.floor(log10_valor)
    return f"{10 ** (log10_valor - exponente):.{decimales}f} × 10^{exponente}"


def _tiempo(log10_anios):
    """Pasa un log10(años) a la unidad que se entienda: ms, segundos o años."""
    log10_seg = log10_anios + math.log10(SEGUNDOS_POR_ANIO)
    if log10_seg < 0:
        return f"{10 ** (log10_seg + 3):.1f} milisegundos"
    if log10_seg < math.log10(86_400):                  # menos de un día
        return f"{10 ** log10_seg:,.1f} segundos"
    if log10_anios < 0:                                 # menos de un año
        return f"{10 ** (log10_seg - math.log10(86_400)):,.1f} días"
    return f"{_diez(log10_anios)} años"


def estimar_rotura(bits):
    """
    Devuelve el tiempo estimado de romper un n de 'bits' bits, en log10(años):
      'rho'  -> con Pollard rho y la velocidad medida de esta máquina
      'gnfs' -> con GNFS, escalando el récord RSA-250
    """
    pasos_por_s = _velocidad_rho(bits)
    log10_pasos = (bits / 4) * math.log10(2)          # sqrt(p) ≈ 2^(bits/4)
    log10_rho = (log10_pasos - math.log10(pasos_por_s)
                 - math.log10(SEGUNDOS_POR_ANIO))
    log10_gnfs = (math.log10(ANIOS_CPU_RECORD)
                  + _log10_ops_gnfs(bits) - _log10_ops_gnfs(BITS_RECORD))
    return {"pasos_por_s": pasos_por_s, "rho": log10_rho, "gnfs": log10_gnfs}


def mostrar_estimacion(bits):
    """Imprime cuánto costaría romper una clave de 'bits' bits."""
    est = estimar_rotura(bits)
    veces_universo = est["rho"] - math.log10(EDAD_UNIVERSO)
    con_granja = est["gnfs"] - math.log10(NUCLEOS_GRANJA)
    comparacion = ", como la de tu banco" if bits >= 2048 else ""

    print(negrita(amarillo(f"\n⏳ ¿Cuánto tardaría en romper una clave de "
                           f"{bits} bits{comparacion}?")))
    print(f"   Esta máquina hace {est['pasos_por_s']:,.0f} pasos de Pollard rho "
          "por segundo.")
    print(f"   · Pollard rho (lo que uso aquí): ~2^{bits // 4} pasos  ->  "
          f"{cian(_tiempo(est['rho']))}")
    if veces_universo > 0:
        print(gris(f"       = {_diez(veces_universo)} veces la edad del universo "
                   f"({EDAD_UNIVERSO:.2e} años)"))

    if bits >= 512:
        print(f"   · GNFS, el mejor algoritmo conocido  ->  "
              f"{cian(_tiempo(est['gnfs']))} de CPU")
        print(gris(f"       calibrado con el récord real: RSA-250 ({BITS_RECORD} bits) "
                   f"costó {ANIOS_CPU_RECORD} años-CPU en 2020"))
        print(gris(f"       repartido entre {NUCLEOS_GRANJA:,} núcleos: "
                   f"{_tiempo(con_granja)}"))
    else:
        print(gris("   · GNFS (el algoritmo de los récords) es una fórmula "
                   "asintótica: para claves tan pequeñas no hace falta,"))
        print(gris("     Pollard rho ya las rompe al instante."))

    # Veredicto según los años-CPU que pediría el mejor algoritmo conocido.
    if est["gnfs"] < 0:                      # menos de un año-CPU
        print(rojo(f"   Conclusión: {bits} bits no protege nada, cae en un rato."))
    elif est["gnfs"] < 6:                    # hasta ~10^6 años-CPU
        print(amarillo(f"   Conclusión: {bits} bits está al alcance de quien tenga "
                       "una granja de servidores."))
        print(amarillo("   Hoy se considera obsoleta: por eso el mínimo son 2048."))
    else:
        print(verde(f"   Conclusión: {bits} bits no es \"imposible de romper\"; es que"))
        print(verde("   no hay tiempo en el universo para romperlo con estos algoritmos."))


def pollard_rho(n, limite_s):
    """Busca un factor de n (Pollard rho, variante de Brent). None si se acaba el tiempo."""
    if n % 2 == 0:
        return 2
    fin = time.time() + limite_s
    while time.time() < fin:
        y, c, m = random.randrange(1, n), random.randrange(1, n), 128
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
                if time.time() > fin:
                    return None
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
    return None


def atacar_clave(nombre, e, n, limite_s):
    """Intenta factorizar n para obtener la clave privada d."""
    with imprimir:
        print(amarillo(f"\n⚔  Atacando la clave de {nombre}: factorizando n "
                       f"({n.bit_length()} bits), máximo {limite_s}s..."))
    t0 = time.time()
    p = pollard_rho(n, limite_s)
    dt = time.time() - t0
    with imprimir:
        if p is None:
            print(verde(f"🛡  No pude factorizar n de {nombre} en {dt:.1f}s. "
                        f"Sin p y q no hay φ(n), sin φ(n) no hay d."))
            est = estimar_rotura(n.bit_length())
            print(gris(f"   (Pollard rho necesitaría ~2^{n.bit_length() // 4} pasos: "
                       f"{_diez(est['rho'])} años en esta máquina. "
                       "Solo veré números.)"))
            return
        q = n // p
        d = inverso_modular(e, (p - 1) * (q - 1))
        claves_rotas[nombre] = (d, n)
        print(rojo(f"💀 ¡Clave de {nombre} ROTA en {dt:.3f}s!"))
        print(rojo(f"   p = {p}\n   q = {q}\n   d = {corto(d)}"))
        print(rojo("   Ahora puedo leer todos los mensajes cifrados para "
                   f"{nombre}. ¡Clave demasiado pequeña!"))


def texto_basura(c):
    """Lo que 've' alguien que interpreta el número cifrado como texto."""
    b = c.to_bytes((c.bit_length() + 7) // 8, "big")
    return b.decode("latin-1").encode("unicode_escape").decode()[:60]


def reenviar(origen, destino, direccion, estado, limite_s):
    """Reenvía frames de 'origen' a 'destino' y los analiza por el camino."""
    try:
        while True:
            cabecera = _recibir_exacto(origen, 4)
            (largo,) = struct.unpack(">I", cabecera)
            cuerpo = _recibir_exacto(origen, largo)
            destino.sendall(cabecera + cuerpo)       # reenvío intacto
            analizar(json.loads(cuerpo), direccion, estado, limite_s)
    except (ConnectionError, OSError):
        with imprimir:
            print(gris(f"\n[{direccion}] conexión cerrada."))
        for s in (origen, destino):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def analizar(paquete, direccion, estado, limite_s):
    tipo = paquete.get("tipo")
    if tipo == "clave":
        nombre, e, n = paquete["nombre"], paquete["e"], paquete["n"]
        estado[direccion] = nombre              # quién habla en esta dirección
        claves_vistas[nombre] = (e, n)
        with imprimir:
            print(negrita(f"\n🔑 [{direccion}] Capturé la clave PÚBLICA de {nombre}"))
            print(f"   e = {e}\n   n = {corto(n)}  [{n.bit_length()} bits]")
        threading.Thread(target=atacar_clave, args=(nombre, e, n, limite_s),
                         daemon=True).start()
    elif tipo == "msg":
        emisor = estado.get(direccion, "?")
        # el mensaje va cifrado con la clave pública del OTRO peer
        receptor = next((k for k in claves_vistas if k != emisor), "?")
        with imprimir:
            print("\n" + "-" * 64)
            print(negrita(f"📡 [{direccion}] Intercepté un mensaje de {emisor} "
                          f"para {receptor}:"))
            for i, c in enumerate(paquete["cifrado"]):
                print(f"   c[{i}] = {cian(corto(c))}")
                print(gris(f"   como texto: {texto_basura(c)}"))
            firma = paquete.get("firma")
            if firma is not None:
                print(f"   s (firma de {emisor}) = {cian(corto(firma))}")
            if receptor in claves_rotas:
                d, n = claves_rotas[receptor]
                salida = bytearray()
                for c in paquete["cifrado"]:
                    m = pow(c, d, n)
                    salida.extend(m.to_bytes((m.bit_length() + 7) // 8, "big")[1:])
                print(rojo(f"   💀 DESCIFRADO CON LA CLAVE ROBADA: "
                           f"{salida.decode('utf-8', 'replace')!r}"))
            else:
                print(verde("   🔒 No tengo d: solo veo números, no el mensaje."))
            if firma is not None and emisor in claves_rotas:
                # Caso clave débil: si rompí la clave del EMISOR tengo su d,
                # así que también puedo firmar en su nombre. Suplantación total.
                print(rojo(f"   💀 Además rompí la clave de {emisor}, así que tengo "
                           f"su d: puedo FIRMAR como {emisor}"))
                print(rojo(f"       y {receptor} creería que el mensaje es suyo. "
                           "La firma solo vale si la clave es fuerte."))
            elif firma is not None:
                print(verde(f"   ✍  La firma la veo, pero no la puedo falsificar: "
                            f"para firmar como {emisor} necesito SU clave privada."))
                print(verde(f"       Si altero el texto, la firma deja de cuadrar y "
                            f"{receptor} lo detecta."))
            print("-" * 64)


def main():
    ap = argparse.ArgumentParser(description="Espía man-in-the-middle")
    ap.add_argument("puerto", nargs="?", type=int, default=6000)
    ap.add_argument("destino_host", nargs="?", default="127.0.0.1")
    ap.add_argument("destino_puerto", nargs="?", type=int, default=5000)
    ap.add_argument("--tiempo", type=int, default=15,
                    help="segundos máximos para intentar factorizar cada n")
    ap.add_argument("--host", default="0.0.0.0",
                    help="interfaz donde escuchar (127.0.0.1 = solo esta PC)")
    ap.add_argument("--estimar", type=int, default=2048,
                    help="bits de la clave para estimar el tiempo de rotura "
                         "(0 = no estimar)")
    args = ap.parse_args()

    print(rojo(negrita("=" * 64)))
    print(rojo(negrita("  ESPÍA EN LA RED  ·  man-in-the-middle pasivo")))
    print(rojo(negrita("=" * 64)))
    print(f"Escuchando en :{args.puerto}  ->  reenviando a "
          f"{args.destino_host}:{args.destino_puerto}")

    if args.estimar > 0:
        mostrar_estimacion(args.estimar)

    try:
        victima_a, addr = escuchar_una_conexion(args.host, args.puerto)
        print(f"Víctima conectada desde {addr[0]}:{addr[1]}")
        victima_b = conectar_con_reintentos(args.destino_host, args.destino_puerto)
        print("Conexión reenviada al otro peer. Ellos no notan nada. 👀")

        estado = {}
        hilos = [
            threading.Thread(target=reenviar, daemon=True,
                             args=(victima_a, victima_b, "→", estado, args.tiempo)),
            threading.Thread(target=reenviar, daemon=True,
                             args=(victima_b, victima_a, "←", estado, args.tiempo)),
        ]
        for h in hilos:
            h.start()
        while any(h.is_alive() for h in hilos):   # join con timeout: Ctrl+C en Windows
            hilos[0].join(0.5)
    except KeyboardInterrupt:
        print("\nEspía detenido.")


if __name__ == "__main__":
    main()
