"""
PEER RECEPTOR (servidor)
========================
1. Genera su par de claves RSA.
2. Escucha conexiones.
3. Cuando un peer se conecta, le ENVÍA su clave pública (e, n).
4. Recibe el mensaje cifrado y lo DESCIFRA con su clave privada.

La clave privada NUNCA sale de esta máquina: eso es la criptografía
de clave pública. Cualquiera puede cifrar para ti; solo tú descifras.

Uso:
    python3 servidor.py                 # puerto 5000, primos de 1024 bits
    python3 servidor.py 5000 512        # puerto y bits por primo a elegir
"""

import socket
import sys

from rsa_core import generar_claves, descifrar_mensaje
from red import enviar_json, recibir_json

HOST = "0.0.0.0"   # escucha en todas las interfaces (LAN incluida)


def main():
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    bits = int(sys.argv[2]) if len(sys.argv) > 2 else 1024

    print("=" * 60)
    print(f"PEER RECEPTOR  ·  generando claves RSA ({2 * bits} bits)...")
    print("=" * 60)
    publica, privada, (p, q) = generar_claves(bits=bits, verboso=True)
    e, n = publica
    print("\nClave privada lista y guardada solo aquí.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, puerto))
        s.listen(1)
        print(f"Esperando a un peer en el puerto {puerto}... (Ctrl+C para salir)")
        conn, addr = s.accept()
        with conn:
            print(f"\nConectado con {addr[0]}:{addr[1]}")

            # Paso 1: enviar la clave pública
            enviar_json(conn, {"e": e, "n": n})
            print("Clave pública enviada al peer.")

            # Paso 2: recibir el cifrado
            paquete = recibir_json(conn)
            cifrado = paquete["cifrado"]
            print(f"\nRecibidos {len(cifrado)} bloque(s) cifrados:")
            for c in cifrado:
                print(f"  {str(c)[:70]}...")

            # Paso 3: descifrar
            mensaje = descifrar_mensaje(cifrado, privada)
            print("\n" + "-" * 60)
            print(f">>> MENSAJE DESCIFRADO: {mensaje!r}")
            print("-" * 60)

            enviar_json(conn, {"ok": True})


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
