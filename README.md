# RSA sobre P2P — Demo de MCD y Coprimalidad

Implementación de RSA **desde cero** (sin librerías externas) para exposición,
más un **ataque de MCD simulado**. Basado en el documento
*"MCD y Coprimalidad en Criptografía"*.

Todo es Python estándar. **No necesitas instalar nada.**

## Archivos

| Archivo          | Qué hace |
|------------------|----------|
| `rsa_core.py`    | El núcleo: Euclides extendido, inverso modular, Miller-Rabin, generación de claves, cifrado/descifrado y firma. |
| `red.py`         | Envío/recepción de mensajes por socket TCP (JSON con framing por longitud). |
| `servidor.py`    | **Peer receptor**: genera claves, comparte la pública, descifra con la privada. |
| `cliente.py`     | **Peer emisor**: recibe la pública, cifra y envía. |
| `ataque_mcd.py`  | **Ataque batch GCD**: rompe claves que comparten un primo (fallo real de 2012). |
| `demo_local.py`  | Todo el ciclo en una sola terminal, ideal para las diapositivas. |
| `peer.py`        | **Chat P2P en tiempo real**, bidireccional, mostrando la fórmula de cada mensaje y **firmando** cada envío. |
| `formula.py`     | Imprime paso a paso `texto → bytes → m → c = mᵉ mod n`, su inverso, la firma y las tablas de Euclides. |
| `mi_clave.py`    | **Construye tu clave a mano**: eliges `p`, `q` y `e`, y enseña toda la matemática división por división. |
| `lanzar_demo.py` | **Menú** que abre las ventanas solo (Linux y Windows). |
| `iniciar_demo.sh` / `.bat` | Doble clic / `./` para arrancar el menú en CachyOS o Windows. |
| `espia.py`       | **Atacante en medio**: intercepta el P2P, ve solo números, intenta romper la clave y **calcula cuánto tardaría con una clave de 2048 bits**. |

---

## 🚀 Inicio rápido (un clic)

El lanzador abre **solo** las 3 ventanas (Harold, Espía, Efrén) en tu PC y
muestra un menú:

```
  1) Chat Harold <-> Efrén con ESPÍA en medio  (clave fuerte 1024 bits)
  2) Chat Harold <-> Efrén con ESPÍA en medio  (clave DÉBIL 64 bits)
  3) Chat Harold <-> Efrén directo, sin espía  (para espiar con Wireshark)
  4) Demo paso a paso en una sola ventana
  5) Ataque de MCD a claves mal generadas
  6) Construye TU clave: eliges p, q y e
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
   Efrén (peer)  ───►  ESPÍA :6000  ───►  Harold (peer) :5000
```

**Terminal 1 — Harold (receptor):**
```bash
python3 peer.py escuchar 5000 --nombre Harold
```

**Terminal 2 — el espía (tu PC haciendo de atacante):**
```bash
python3 espia.py 6000 127.0.0.1 5000
```

**Terminal 3 — Efrén (se conecta pasando por el espía, sin saberlo):**
```bash
python3 peer.py conectar 127.0.0.1 6000 --nombre Efrén
```

Ahora escribe mensajes en Harold o en Efrén. Lo que verán los estudiantes:

| Pantalla | Qué muestra |
|----------|-------------|
| **Emisor** | El texto → bytes → número `m` → `c = m^65537 mod n` (la fórmula en vivo). |
| **Receptor** | `m = c^d mod n` → bytes → el mensaje original. |
| **Espía** | Las claves públicas, los números `c` y "basura" si intenta leerlos como texto. Intenta factorizar `n` y **se rinde**: 🔒 *"solo veo números, no el mensaje"*. |

### Escena 2: ¿por qué importa el tamaño de la clave?

Repite lo mismo agregando `--bits 32` a **Harold y Efrén** (claves de 64 bits):

```bash
python3 peer.py escuchar 5000 --nombre Harold --bits 32
python3 espia.py 6000 127.0.0.1 5000
python3 peer.py conectar 127.0.0.1 6000 --nombre Efrén --bits 32
```

Ahora el espía factoriza `n` en milisegundos, calcula `d` y muestra
💀 *"DESCIFRADO CON LA CLAVE ROBADA"*. La fórmula es la misma; lo que protege
es que `n` sea imposible de factorizar.

### Variante: espiar con Wireshark desde tu PC

Sin usar `espia.py`, conecta Efrén directo a Harold (`peer.py conectar 127.0.0.1 5000`)
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

## 5) Firma digital (¿de verdad lo escribió Efrén?)

El cifrado da **confidencialidad**, pero no dice quién escribió: la clave
pública de Harold la tiene cualquiera, así que cualquiera puede escribirle
diciendo "soy Efrén". La firma añade **autenticidad** e **integridad** usando
RSA al revés:

```
Efrén firma    :  h = SHA-256(texto)      s = h^d_Efrén mod n_Efrén   (clave PRIVADA)
Harold verifica  :  h' = s^e_Efrén mod n_Efrén        ¿h' == SHA-256(texto)?
```

`peer.py` lo hace en cada mensaje sin que tengas que pedir nada: Harold ve
`✔ FIRMA VÁLIDA: el mensaje es de Efrén y nadie lo alteró`, y si el texto o la
firma no cuadran sale `✗ FIRMA INVÁLIDA`. Prueba rápida sin red:

```bash
python3 rsa_core.py      # firma, verifica, y rechaza el texto alterado
```

En la opción 2 del menú (clave débil) el espía rompe la clave de Efrén, así que
también puede **firmar en su nombre**: la firma solo vale si la clave es fuerte.

---

## 6) ¿Cuánto tardaría en romper una clave real?

El espía lo calcula al arrancar, midiendo la velocidad de **tu** máquina:

```bash
python3 espia.py --estimar 2048     # por defecto; 0 = no estimar
python3 espia.py --estimar 4096
```

- **Pollard rho** (el método que usa el espía): ~`2^(bits/4)` pasos → para 2048
  bits, del orden de `10^141` años, o `10^131` veces la edad del universo.
- **GNFS** (el mejor algoritmo conocido), calibrado con el récord real
  **RSA-250** (829 bits, ~2700 años-CPU en 2020): del orden de `10^14`
  años-CPU para 2048 bits; incluso con un millón de núcleos, `10^8` años.

Con 1024 bits el mismo cálculo da ~`10^5` años-CPU: al alcance de una granja
grande, y por eso hoy el mínimo recomendado es 2048.

---

## 7) Construye tu propia clave (eliges tú los números)

La opción **6** del menú, o directamente:

```bash
python3 mi_clave.py            # te pregunta p, q y e
python3 mi_clave.py 61 53 17   # con los números ya puestos
```

Pulsando Enter aceptas el ejemplo clásico de los libros —`p = 61`, `q = 53`,
`e = 17`— y salen `n = 3233`, `φ(n) = 3120` y `d = 2753`, los mismos números
que puedes escribir en el pizarrón.

**Lo que enseña, paso por paso:**

1. **Valida tus primos** con Miller-Rabin. Si metes 9 te dice que no es primo y
   por qué importa; si repites `p = q` te explica que entonces `n = p²` y sacar
   `p` es solo una raíz cuadrada.
2. **`n = p·q` y `φ(n) = (p-1)(q-1)`** con la multiplicación a la vista.
3. **`mcd(e, φ(n))` con la tabla completa de Euclides**, división por división.
   Si eliges un `e` que no sirve, lo ves fallar:

   ```
   ── MCD por Euclides: mcd(5, 3120) ──
     3120 = 624 × 5 + 0
     resto 0  ->  mcd = 5
   mcd(5, 3120) ≠ 1: NO son coprimos, así que e no
   tiene inverso módulo φ(n) y no existiría d. Elige otro.
   ```

4. **`d = e⁻¹ mod φ(n)` con Euclides extendido en tabla**, con los coeficientes
   de Bézout y el ajuste del negativo:

   ```
   cociente     r     s    t
   -------------------------
              3120     0    1
        183     9  -183    1
          1     8   184   -1
          1     1  -367    2
   Bézout: 1 = -367·17 + 2·3120
   s = -367 es negativo, se ajusta: -367 mod 3120 = 2753
   d = 2753
   ```

   Y la comprobación: `17 × 2753 = 46801`, y `46801 mod 3120 = 1` ✔

5. **Cifra y descifra con tus números.** Si tu clave es chica (menos de 17 bits)
   no cabe ni un byte de texto, así que cifra un **número** que elijas:
   `c = 42^17 mod 3233 = 2557`, y de vuelta `2557^2753 mod 3233 = 42`. Con
   primos de 3 cifras (`257` y `263`) ya cabe texto y lo cifra letra a letra.
6. **Firma y verifica**, y además cambia el texto para que veas cómo la firma
   deja de cuadrar.

---

## Cómo funciona (resumen)

1. El receptor genera `p`, `q` primos → `n = p·q` y `φ(n) = (p-1)(q-1)`.
2. Elige `e = 65537` con **`mcd(e, φ(n)) = 1`** (coprimalidad → hay inverso).
3. Calcula `d = e⁻¹ mod φ(n)` con **Euclides extendido**.
4. Cifrar: `c = mᵉ mod n`. Descifrar: `m = cᵈ mod n`.
5. **Firmar**: `s = hᵈ mod n` con la privada; verificar: `h = sᵉ mod n` con la
   pública (`h` = SHA-256 del texto, reducido mod `n`).
6. **Ataque**: si `n1 = p·q1` y `n2 = p·q2`, entonces `mcd(n1, n2) = p`
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
- *"Añade padding OAEP para que el cifrado no sea determinista."*
