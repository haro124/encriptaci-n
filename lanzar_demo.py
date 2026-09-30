"""
LANZADOR DE LA DEMO (Linux/CachyOS y Windows)
=============================================
Abre automáticamente una ventana por cada participante:

    Efrén  ───►  ESPÍA :6000  ───►  Harold :5000

Todo corre en esta misma PC (127.0.0.1). No hace falta instalar nada
aparte de Python 3.

Uso:
    python3 lanzar_demo.py            # menú interactivo
    python3 lanzar_demo.py 1          # opción directa (1-5)

Normalmente se ejecuta con iniciar_demo.sh (Linux) o iniciar_demo.bat (Windows).
"""

import os
import shlex
import shutil
import subprocess
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
ES_WINDOWS = os.name == "nt"

MENU = """
========================================================================
   RSA sobre P2P · DEMO PARA LA EXPOSICIÓN
========================================================================
  1) Chat Harold <-> Efrén con ESPÍA en medio  (clave fuerte 1024 bits)
  2) Chat Harold <-> Efrén directo, sin espía  (para espiar con Wireshark)
  3) Demo paso a paso en una sola ventana      (demo_local.py)
  4) Ataque de MCD a claves mal generadas      (ataque_mcd.py)
  5) Construye TU clave: eliges p, q y e       (mi_clave.py)
  0) Salir
"""


# ---------------------------------------------------------------------------
# Abrir una ventana de terminal nueva con un comando
# ---------------------------------------------------------------------------
def _terminal_linux(titulo, cmd):
    """Devuelve la lista para Popen según la terminal instalada."""
    # 'bash -c' deja la ventana abierta al terminar para poder leer la salida
    linea = f"{shlex.join(cmd)}; echo; read -p 'Pulsa Enter para cerrar...'"
    shell = ["bash", "-c", linea]
    opciones = [
        ("konsole",        ["konsole", "-p", f"tabtitle={titulo}", "-e", *shell]),
        ("gnome-terminal", ["gnome-terminal", f"--title={titulo}", "--", *shell]),
        ("ptyxis",         ["ptyxis", "--new-window", "--", *shell]),
        ("kgx",            ["kgx", f"--title={titulo}", "-e", shlex.join(shell)]),
        ("kitty",          ["kitty", "--title", titulo, *shell]),
        ("alacritty",      ["alacritty", "--title", titulo, "-e", *shell]),
        ("wezterm",        ["wezterm", "start", "--", *shell]),
        ("foot",           ["foot", "--title", titulo, *shell]),
        ("xfce4-terminal", ["xfce4-terminal", f"--title={titulo}", "-x", *shell]),
        ("mate-terminal",  ["mate-terminal", f"--title={titulo}", "-x", *shell]),
        ("lxterminal",     ["lxterminal", f"--title={titulo}", "-e", shlex.join(shell)]),
        ("xterm",          ["xterm", "-T", titulo, "-e", *shell]),
    ]
    preferida = os.environ.get("TERMINAL")
    if preferida:
        opciones.sort(key=lambda o: o[0] != os.path.basename(preferida))
    for nombre, argv in opciones:
        if shutil.which(nombre):
            return argv
    return None


def abrir_ventana(titulo, script, *args):
    cmd = [PY, os.path.join(AQUI, script), *args]
    if ES_WINDOWS:
        # cmd /k deja la ventana abierta; CREATE_NEW_CONSOLE abre una ventana nueva
        linea = f'title {titulo} & {subprocess.list2cmdline(cmd)}'
        subprocess.Popen(f'cmd /k "{linea}"', cwd=AQUI,
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True
    argv = _terminal_linux(titulo, cmd)
    if argv is None:
        print("No encontré una terminal gráfica (konsole, kitty, alacritty...).")
        print("Abre 3 terminales a mano y ejecuta:")
        return False
    subprocess.Popen(argv, cwd=AQUI, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return True


# ---------------------------------------------------------------------------
# Escenarios
# ---------------------------------------------------------------------------
def chat(bits, con_espia):
    local = ["--host", "127.0.0.1"]           # solo esta PC: sin aviso del firewall
    bits_arg = ["--bits", str(bits)]
    ventanas = [("Harold (receptor)", "peer.py",
                 ["escuchar", "5000", "--nombre", "Harold", *bits_arg, *local])]
    if con_espia:
        ventanas.append(("ESPIA (atacante)", "espia.py",
                         ["6000", "127.0.0.1", "5000", *local]))
        ventanas.append(("Efrén (emisor)", "peer.py",
                         ["conectar", "127.0.0.1", "6000", "--nombre", "Efrén", *bits_arg]))
    else:
        ventanas.append(("Efrén (emisor)", "peer.py",
                         ["conectar", "127.0.0.1", "5000", "--nombre", "Efrén", *bits_arg]))

    for titulo, script, args in ventanas:
        if not abrir_ventana(titulo, script, *args):
            for _, s, a in ventanas:
                print("   ", shlex.join([PY, s, *a]) if not ES_WINDOWS
                      else subprocess.list2cmdline([PY, s, *a]))
            return
        time.sleep(1.0)                      # orden: Harold, espía, Efrén

    print(f"\nAbiertas {len(ventanas)} ventanas. Escribe mensajes en Harold o en Efrén.")
    if not con_espia:
        print("Wireshark: interfaz loopback ('lo' en Linux, 'Adapter for loopback "
              "traffic capture' en Windows), filtro:  tcp.port == 5000")


def en_esta_ventana(script):
    subprocess.call([PY, os.path.join(AQUI, script)], cwd=AQUI)


def main():
    opcion = sys.argv[1] if len(sys.argv) > 1 else None
    while True:
        if opcion is None:
            print(MENU)
            opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            chat(512, con_espia=True)
        elif opcion == "2":
            chat(512, con_espia=False)
        elif opcion == "3":
            en_esta_ventana("demo_local.py")
        elif opcion == "4":
            en_esta_ventana("ataque_mcd.py")
        elif opcion == "5":
            en_esta_ventana("mi_clave.py")
        elif opcion in ("0", "q", ""):
            return
        else:
            print("Opción no válida.")
        if len(sys.argv) > 1:
            return
        opcion = None


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
