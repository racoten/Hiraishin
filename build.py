#!/usr/bin/env python3
"""
build.py -- Hiraishin WorkMask PICO build script (cross-platform)

Usage:
    python build.py                 # compile + encrypt
    python build.py --clean         # remove bin/
    python build.py --pico          # compile + encrypt + Crystal Palace link
    python build.py --cc clang      # use a different compiler
"""

import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN  = os.path.join(ROOT, "bin")

CFLAGS = [
    "-DWIN_X64", "-c", "-masm=intel", "-Wall",
    "-Wno-pointer-arith", "-Wno-int-to-pointer-cast",
    "-fno-toplevel-reorder", "-fno-jump-tables",
    "-fno-exceptions", "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    f"-I{os.path.join(ROOT, 'include')}",
    "-O1",
]


def run(cmd, label):
    print(f"  [{label}] {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        print(f"  FAILED (exit {r.returncode})")
        sys.exit(1)


def find_compiler():
    for name in ["x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-gcc-posix"]:
        if shutil.which(name):
            return name
    return None


def main():
    parser = argparse.ArgumentParser(description="Build Hiraishin WorkMask PICO")
    parser.add_argument("--clean", action="store_true", help="Remove bin/ and exit")
    parser.add_argument("--pico", action="store_true", help="Also link with Crystal Palace")
    parser.add_argument("--cc", default=None, help="C compiler (default: auto-detect mingw)")
    parser.add_argument("--cp-jar", default="crystalpalace.jar", help="Path to Crystal Palace JAR")
    parser.add_argument("--python", default=sys.executable, help="Python interpreter")
    args = parser.parse_args()

    if args.clean:
        if os.path.isdir(BIN):
            shutil.rmtree(BIN)
        print("Cleaned.")
        return

    cc = args.cc or find_compiler()
    if not cc:
        print("No MinGW cross-compiler found.")
        print("Install: apt install gcc-mingw-w64-x86-64  (Linux)")
        print("         pacman -S mingw-w64-ucrt-x86_64-gcc  (MSYS2)")
        print("         brew install mingw-w64  (macOS)")
        print("Or pass --cc <compiler>")
        sys.exit(1)

    os.makedirs(BIN, exist_ok=True)

    workmask_o  = os.path.join(BIN, "workmask.x64.o")
    funcs_o     = os.path.join(BIN, "protected_funcs.x64.o")
    funcs_enc_o = os.path.join(BIN, "protected_funcs.enc.x64.o")
    pico_bin    = os.path.join(BIN, "hiraishin.pico.bin")

    print()
    print("  Hiraishin WorkMask PICO — Build")
    print("  ================================")
    print(f"  CC:     {cc}")
    print(f"  Python: {args.python}")
    print()

    run([cc] + CFLAGS + ["-o", workmask_o, os.path.join("src", "workmask.c")],
        "1/3 workmask.c")

    run([cc] + CFLAGS + ["-o", funcs_o, os.path.join("src", "protected_funcs.c")],
        "2/3 protected_funcs.c")

    run([args.python, os.path.join("tools", "hir_encrypt.py"),
         "--obj", funcs_o, "--output", funcs_enc_o],
        "3/3 encrypt")

    print()
    print(f"  Output:")
    print(f"    {workmask_o}")
    print(f"    {funcs_enc_o}")
    print()

    if args.pico:
        print("  [PICO] Linking with Crystal Palace...")
        run(["java", "-jar", args.cp_jar, "buildPic",
             os.path.join(ROOT, "hiraishin.spec"), "x64", pico_bin],
            "PICO link")
        print(f"    {pico_bin}")
        print()

    print("  Done.")


if __name__ == "__main__":
    main()
