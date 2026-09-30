"""
Utilidades de red para el canal entre los dos peers.

Usamos sockets TCP y enviamos JSON con "framing" por longitud:
cada mensaje va precedido de 4 bytes que indican su tamaño. Así el
receptor sabe exactamente cuántos bytes leer (evita mensajes cortados).
"""

import json
import socket
import struct
import time


def _recibir_exacto(sock, cantidad):
    """Lee exactamente 'cantidad' bytes del socket o lanza error si se corta."""
    datos = bytearray()
    while len(datos) < cantidad:
        parte = sock.recv(cantidad - len(datos))
        if not parte:
            raise ConnectionError("La conexión se cerró antes de tiempo.")
        datos.extend(parte)
    return bytes(datos)


def enviar_json(sock, objeto):
    """Serializa 'objeto' a JSON y lo envía con cabecera de longitud."""
    datos = json.dumps(objeto).encode("utf-8")
    sock.sendall(struct.pack(">I", len(datos)) + datos)


def recibir_json(sock):
    """Recibe un objeto JSON completo."""
    (longitud,) = struct.unpack(">I", _recibir_exacto(sock, 4))
    return json.loads(_recibir_exacto(sock, longitud).decode("utf-8"))


def escuchar_una_conexion(host, puerto):
    """
    Espera UNA conexión entrante. Usa un timeout corto en el bucle para
    que Ctrl+C funcione también en Windows (allí accept() lo bloquea).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, puerto))
        srv.listen(1)
        srv.settimeout(1.0)
        while True:
            try:
                conn, addr = srv.accept()
                conn.settimeout(None)
                return conn, addr
            except socket.timeout:
                continue


def conectar_con_reintentos(host, puerto, segundos=60):
    """Conecta a host:puerto reintentando mientras el otro peer arranca."""
    limite = time.time() + segundos
    while True:
        try:
            return socket.create_connection((host, puerto))
        except (ConnectionRefusedError, OSError):
            if time.time() > limite:
                raise
            time.sleep(0.5)
