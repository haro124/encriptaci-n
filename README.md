# RSA sobre P2P — Demo de MCD y Coprimalidad

Implementación de RSA **desde cero** (sin librerías externas) para exposición,
más un **ataque de MCD simulado**. Basado en el documento
*"MCD y Coprimalidad en Criptografía"*.

Todo es Python estándar. **No necesitas instalar nada.**

## Archivos

| Archivo          | Qué hace |
|------------------|----------|
| `rsa_core.py`    | El núcleo: Euclides extendido, inverso modular, Miller-Rabin, generación de claves, cifrado/descifrado. |
| `red.py`         | Envío/recepción de mensajes por socket TCP (JSON con framing por longitud). |
| `servidor.py`    | **Peer receptor**: genera claves, comparte la pública, descifra con la privada. |
| `cliente.py`     | **Peer emisor**: recibe la pública, cifra y envía. |
| `ataque_mcd.py`  | **Ataque batch GCD**: rompe claves que comparten un primo (fallo real de 2012). |
| `demo_local.py`  | Todo el ciclo en una sola terminal, ideal para las diapositivas. |

---

## 1) Demo rápida para la exposición (una sola terminal)

Muestra keygen paso a paso, cifrado, descifrado y ataque, sin red:

```bash
python3 demo_local.py
python3 demo_local.py "Mi mensaje secreto"
```

---

## 2) Demo por red — misma PC (modo prueba)

Abre **dos terminales** en esta carpeta.

**Terminal 1 (receptor):**
```bash
python3 servidor.py
```

**Terminal 2 (emisor):**
```bash
python3 cliente.py 127.0.0.1 "Hola, esto va cifrado con RSA"
```

El receptor imprime el mensaje descifrado. Genera claves de **2048 bits**
(el estándar real), tarda ~2 s. Para que sea instantáneo en clase:

```bash
python3 servidor.py 5000 512      # puerto 5000, primos de 512 bits
python3 cliente.py 127.0.0.1 "Hola" 5000
```

---

## 3) Demo por red — dos PCs (exposición P2P real)

En la PC que **recibe** (averigua su IP con `ip a` o `hostname -I`):
```bash
python3 servidor.py
```

En la PC que **envía**, usa la IP de la otra:
```bash
python3 cliente.py 192.168.1.50 "Hola desde la otra maquina"
```

> Ambas PCs deben estar en la misma red. Si no conecta, abre el puerto 5000
> en el firewall del receptor:
> `sudo ufw allow 5000/tcp`

---

## 4) Ataque de MCD simulado

Demuestra que si dos claves comparten un primo, un solo MCD las rompe
(sin factorizar). Las claves bien generadas resisten:

```bash
python3 ataque_mcd.py
python3 ataque_mcd.py 512     # primos más grandes
```

---

## Cómo funciona (resumen)

1. El receptor genera `p`, `q` primos → `n = p·q` y `φ(n) = (p-1)(q-1)`.
2. Elige `e = 65537` con **`mcd(e, φ(n)) = 1`** (coprimalidad → hay inverso).
3. Calcula `d = e⁻¹ mod φ(n)` con **Euclides extendido**.
4. Cifrar: `c = mᵉ mod n`. Descifrar: `m = cᵈ mod n`.
5. **Ataque**: si `n1 = p·q1` y `n2 = p·q2`, entonces `mcd(n1, n2) = p`
   y ambas claves caen.

⚠️ Esto es **RSA "de libro"** con fines educativos: no usa relleno (padding
OAEP). No lo uses para proteger datos reales — para eso están librerías como
`cryptography`.

---

## Seguir con Claude Code

Abre esta carpeta en Claude Code (`claude` en la terminal) y pídele mejoras, por ejemplo:

- *"Agrega cifrado híbrido: RSA para intercambiar una clave AES y AES para el mensaje."*
- *"Hazme una interfaz web con Flask para la demo."*
- *"Implementa el batch GCD eficiente (árbol de productos) para miles de claves."*
- *"Agrega firma digital: firmar con la privada y verificar con la pública."*
