"""
Utilidades de red para el canal entre los dos peers.

Usamos sockets TCP y enviamos JSON con "framing" por longitud:
cada mensaje va precedido de 4 bytes que indican su tamaño. Así el
receptor sabe exactamente cuántos bytes leer (evita mensajes cortados).
"""

import json
import struct


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
