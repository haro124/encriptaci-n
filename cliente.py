"""
PEER EMISOR (cliente)
=====================
1. Se conecta al peer receptor.
2. RECIBE su clave pública (e, n).
3. Cifra el mensaje con esa clave pública.
4. Envía el mensaje cifrado.

Solo el receptor (que tiene d) podrá descifrarlo. Ni siquiera este
programa puede volver a leer el texto una vez cifrado.

Uso:
    python3 cliente.py                                  # localhost, mensaje por defecto
    python3 cliente.py 127.0.0.1 "Hola mundo"           # host y mensaje
    python3 cliente.py 192.168.1.50 "Hola" 5000         # host, mensaje y puerto (otra PC)
"""

import socket
import sys

from rsa_core import cifrar_mensaje
from red import enviar_json, recibir_json


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    mensaje = sys.argv[2] if len(sys.argv) > 2 else "Hola, esto va cifrado con RSA 🔐"
    puerto = int(sys.argv[3]) if len(sys.argv) > 3 else 5000

    print("=" * 60)
    print(f"PEER EMISOR  ·  conectando a {host}:{puerto}...")
    print("=" * 60)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, puerto))

        # Paso 1: recibir la clave pública del receptor
        publica = recibir_json(s)
        e, n = publica["e"], publica["n"]
        print("Clave pública recibida:")
        print(f"  e = {e}")
        print(f"  n = {str(n)[:70]}...  ({n.bit_length()} bits)")

        # Paso 2: cifrar
        print(f"\nMensaje original : {mensaje!r}")
        cifrado = cifrar_mensaje(mensaje, (e, n))
        print(f"Cifrado en {len(cifrado)} bloque(s):")
        for c in cifrado:
            print(f"  {str(c)[:70]}...")

        # Paso 3: enviar
        enviar_json(s, {"cifrado": cifrado})
        recibir_json(s)  # espera confirmación
        print("\nEl peer receptor recibió y descifró el mensaje ✔")


if __name__ == "__main__":
    main()
