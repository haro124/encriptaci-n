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

Esquema en una sola PC:

    Beto (peer)  --->  espía :6000  --->  Ana (peer) :5000

Uso:
    python3 espia.py                          # escucha 6000, reenvía a 127.0.0.1:5000
    python3 espia.py 6000 127.0.0.1 5000 --tiempo 20

Luego Ana:   python3 peer.py escuchar 5000 --nombre Ana
y Beto:      python3 peer.py conectar 127.0.0.1 6000 --nombre Beto
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
from red import _recibir_exacto
from rsa_core import inverso_modular

claves_rotas = {}          # nombre del dueño de la clave -> (d, n)
claves_vistas = {}         # nombre -> (e, n)
imprimir = threading.Lock()


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
            print(gris(f"   (Con {n.bit_length()} bits tardaría más que la edad "
                       f"del universo. Solo veré números.)"))
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
            print("-" * 64)


def main():
    ap = argparse.ArgumentParser(description="Espía man-in-the-middle")
    ap.add_argument("puerto", nargs="?", type=int, default=6000)
    ap.add_argument("destino_host", nargs="?", default="127.0.0.1")
    ap.add_argument("destino_puerto", nargs="?", type=int, default=5000)
    ap.add_argument("--tiempo", type=int, default=15,
                    help="segundos máximos para intentar factorizar cada n")
    args = ap.parse_args()

    print(rojo(negrita("=" * 64)))
    print(rojo(negrita("  ESPÍA EN LA RED  ·  man-in-the-middle pasivo")))
    print(rojo(negrita("=" * 64)))
    print(f"Escuchando en :{args.puerto}  ->  reenviando a "
          f"{args.destino_host}:{args.destino_puerto}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.puerto))
        srv.listen(1)
        victima_a, addr = srv.accept()
        print(f"Víctima conectada desde {addr[0]}:{addr[1]}")
        victima_b = socket.create_connection((args.destino_host, args.destino_puerto))
        print("Conexión reenviada al otro peer. Ellos no notan nada. 👀")

        estado = {}
        t1 = threading.Thread(target=reenviar, daemon=True,
                              args=(victima_a, victima_b, "→", estado, args.tiempo))
        t2 = threading.Thread(target=reenviar, daemon=True,
                              args=(victima_b, victima_a, "←", estado, args.tiempo))
        t1.start(); t2.start()
        try:
            t1.join(); t2.join()
        except KeyboardInterrupt:
            print("\nEspía detenido.")


if __name__ == "__main__":
    main()
