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
| `peer.py`        | **Chat P2P en tiempo real**, bidireccional, mostrando la fórmula de cada mensaje. |
| `formula.py`     | Imprime paso a paso `texto → bytes → m → c = mᵉ mod n` y su inverso. |
| `lanzar_demo.py` | **Menú** que abre las ventanas solo (Linux y Windows). |
| `iniciar_demo.sh` / `.bat` | Doble clic / `./` para arrancar el menú en CachyOS o Windows. |
| `espia.py`       | **Atacante en medio**: intercepta el P2P, ve solo números e intenta romper la clave. |

---

## 🚀 Inicio rápido (un clic)

El lanzador abre **solo** las 3 ventanas (Ana, Espía, Beto) en tu PC y
muestra un menú:

```
  1) Chat Ana <-> Beto con ESPÍA en medio  (clave fuerte 1024 bits)
  2) Chat Ana <-> Beto con ESPÍA en medio  (clave DÉBIL 64 bits)
  3) Chat Ana <-> Beto directo, sin espía  (para espiar con Wireshark)
  4) Demo paso a paso en una sola ventana
  5) Ataque de MCD a claves mal generadas
```

### 🐧 CachyOS / Arch Linux

Python ya viene instalado en CachyOS (si no: `sudo pacman -S python`).

```bash
cd rsa_p2p_exposicion
chmod +x iniciar_demo.sh      # solo la primera vez
./iniciar_demo.sh
```

Detecta tu terminal sola (Konsole, Kitty, Alacritty, GNOME Terminal, Ptyxis,
Foot, WezTerm, xterm…). Para forzar una: `TERMINAL=kitty ./iniciar_demo.sh`.

### 🪟 Windows 10 / 11

1. Instala Python 3 desde <https://www.python.org/downloads/> y marca
   **"Add python.exe to PATH"** durante la instalación.
2. Descomprime la carpeta y haz **doble clic en `iniciar_demo.bat`**.

Se abren 3 ventanas de consola. Todo escucha solo en `127.0.0.1`, así que el
firewall de Windows no debería mostrar ningún aviso.

### Wireshark (opcional, opción 3 del menú)

- **CachyOS:** `sudo pacman -S wireshark-qt` y `sudo usermod -aG wireshark $USER`
  (cierra sesión y vuelve a entrar). Captura en la interfaz `lo`.
- **Windows:** instala Wireshark con **Npcap** marcando *"Support loopback
  traffic capture"*. Captura en *"Adapter for loopback traffic capture"*.
- Filtro: `tcp.port == 5000` → clic derecho → *Follow → TCP Stream*.

---

## ⭐ Guía para la exposición (paso a paso, a mano)

Si prefieres abrir las terminales tú mismo: abre **3 terminales** en esta
carpeta (en Windows usa `python` en vez de `python3`).

```
   Beto (peer)  ───►  ESPÍA :6000  ───►  Ana (peer) :5000
```

**Terminal 1 — Ana (receptor):**
```bash
python3 peer.py escuchar 5000 --nombre Ana
```

**Terminal 2 — el espía (tu PC haciendo de atacante):**
```bash
python3 espia.py 6000 127.0.0.1 5000
```

**Terminal 3 — Beto (se conecta pasando por el espía, sin saberlo):**
```bash
python3 peer.py conectar 127.0.0.1 6000 --nombre Beto
```

Ahora escribe mensajes en Ana o en Beto. Lo que verán los estudiantes:

| Pantalla | Qué muestra |
|----------|-------------|
| **Emisor** | El texto → bytes → número `m` → `c = m^65537 mod n` (la fórmula en vivo). |
| **Receptor** | `m = c^d mod n` → bytes → el mensaje original. |
| **Espía** | Las claves públicas, los números `c` y "basura" si intenta leerlos como texto. Intenta factorizar `n` y **se rinde**: 🔒 *"solo veo números, no el mensaje"*. |

### Escena 2: ¿por qué importa el tamaño de la clave?

Repite lo mismo agregando `--bits 32` a **Ana y Beto** (claves de 64 bits):

```bash
python3 peer.py escuchar 5000 --nombre Ana --bits 32
python3 espia.py 6000 127.0.0.1 5000
python3 peer.py conectar 127.0.0.1 6000 --nombre Beto --bits 32
```

Ahora el espía factoriza `n` en milisegundos, calcula `d` y muestra
💀 *"DESCIFRADO CON LA CLAVE ROBADA"*. La fórmula es la misma; lo que protege
es que `n` sea imposible de factorizar.

### Variante: espiar con Wireshark desde tu PC

Sin usar `espia.py`, conecta Beto directo a Ana (`peer.py conectar 127.0.0.1 5000`)
y abre Wireshark capturando en la interfaz **loopback** (en Windows:
*"Adapter for loopback traffic capture"*, en Linux: `lo`) con el filtro:

```
tcp.port == 5000
```

Clic derecho sobre un paquete → *Follow → TCP Stream*: se ve el JSON con
`"cifrado": [7883811491...]` — números, nunca el texto.

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
