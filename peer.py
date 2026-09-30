"""
CHAT P2P CIFRADO CON RSA EN TIEMPO REAL
=======================================
Cada peer genera sus propias claves e intercambia la clave pública con el
otro. Todo lo que escribes se cifra con la clave pública del otro peer, y
en pantalla se ve la fórmula paso a paso. Es bidireccional: ambos pueden
escribir.

    Tú escribes "Hola"  ->  m = 0x01486f6c61  ->  c = m^e mod n  ->  red
    El otro recibe c    ->  m = c^d mod n     ->  "Hola"

Además cada mensaje va FIRMADO con la clave privada de quien lo envía, así
que el receptor puede probar quién lo escribió (autenticidad) y que nadie
lo cambió en el camino (integridad):

    Efrén firma :  s = h^d_Efrén mod n_Efrén        (h = SHA-256 del texto)
    Harold verifica:  h' = s^e_Efrén mod n_Efrén  ->  ¿h' == SHA-256(texto)?

Uso (misma PC, dos terminales):
    python3 peer.py escuchar 5000 --nombre Harold
    python3 peer.py conectar 127.0.0.1 5000 --nombre Efrén

Con el espía en medio (ver espia.py), Efrén se conecta al espía:
    python3 peer.py conectar 127.0.0.1 6000 --nombre Efrén

Opciones:
    --bits N   bits de CADA primo (defecto 512 -> n de 1024 bits).
               Usa --bits 32 para una clave débil que el espía SÍ rompe.
"""

import argparse
import threading

from formula import (mostrar_clave, cifrar_explicado, descifrar_explicado,
                     firmar_explicado, verificar_explicado,
                     verde, rojo, negrita, gris)
from red import (enviar_json, recibir_json, escuchar_una_conexion,
                 conectar_con_reintentos)
from rsa_core import generar_claves


def escuchar_mensajes(conn, privada, nombre_otro, publica_otro):
    """
    Hilo que recibe, descifra, VERIFICA LA FIRMA y muestra los mensajes.

    Descifrar usa la clave privada propia; verificar usa la clave PÚBLICA
    del otro peer. Son dos cosas distintas: una da secreto, la otra prueba
    quién escribió.
    """
    try:
        while True:
            paquete = recibir_json(conn)
            if paquete.get("tipo") != "msg":
                continue
            print("\n" + "=" * 64)
            print(negrita(f"📥 Llegó un mensaje cifrado de {nombre_otro}"))
            texto = descifrar_explicado(paquete["cifrado"], privada)
            autentico = verificar_explicado(texto, paquete.get("firma"),
                                            publica_otro, nombre_otro)
            if autentico:
                print(verde(f"  {nombre_otro} dice: {texto}"))
            else:
                print(rojo(f"  ⚠ Mensaje NO autenticado (¿impostor?): {texto}"))
            print("=" * 64)
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        print(rojo(f"\n{nombre_otro} se desconectó."))


def main():
    ap = argparse.ArgumentParser(description="Chat P2P cifrado con RSA")
    ap.add_argument("modo", choices=["escuchar", "conectar"])
    ap.add_argument("destino", nargs="*",
                    help="escuchar: [puerto]  ·  conectar: host [puerto]")
    ap.add_argument("--nombre", default=None)
    ap.add_argument("--bits", type=int, default=512,
                    help="bits de cada primo (defecto 512)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="interfaz donde escuchar (127.0.0.1 = solo esta PC)")
    args = ap.parse_args()
    nombre = args.nombre or ("Receptor" if args.modo == "escuchar" else "Emisor")

    print(negrita(f"Generando claves RSA para {nombre} ({2 * args.bits} bits)..."))
    publica, privada, _ = generar_claves(bits=args.bits)
    mostrar_clave(nombre, publica, privada)

    if args.modo == "escuchar":
        puerto = int(args.destino[0]) if args.destino else 5000
        print(f"\nEsperando a un peer en el puerto {puerto}...")
        conn, addr = escuchar_una_conexion(args.host, puerto)
        print(f"Conectado con {addr[0]}:{addr[1]}")
    else:
        host = args.destino[0] if args.destino else "127.0.0.1"
        puerto = int(args.destino[1]) if len(args.destino) > 1 else 5000
        print(f"\nConectando a {host}:{puerto}...")
        conn = conectar_con_reintentos(host, puerto)
        print(f"Conectado a {host}:{puerto}")

    # Intercambio de claves públicas (la privada nunca viaja)
    e, n = publica
    enviar_json(conn, {"tipo": "clave", "nombre": nombre, "e": e, "n": n})
    clave_otro = recibir_json(conn)
    nombre_otro = clave_otro["nombre"]
    publica_otro = (clave_otro["e"], clave_otro["n"])
    print()
    mostrar_clave(nombre_otro, publica_otro)

    threading.Thread(target=escuchar_mensajes,
                     args=(conn, privada, nombre_otro, publica_otro),
                     daemon=True).start()

    print(gris("\nEscribe un mensaje y pulsa Enter (Ctrl+C para salir).\n"))
    try:
        while True:
            texto = input("> ")
            if not texto:
                continue
            cifrado = cifrar_explicado(texto, publica_otro)
            firma = firmar_explicado(texto, privada, nombre)
            enviar_json(conn, {"tipo": "msg", "cifrado": cifrado, "firma": firma})
            print(verde(f"📤 Enviado a {nombre_otro} "
                        f"(solo viajan los números c y la firma s)\n"))
    except (KeyboardInterrupt, EOFError):
        print("\nSaliendo.")
    except (ConnectionError, OSError):
        print(rojo("La conexión se cerró."))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
