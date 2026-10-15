"""Build a shareable, source-free package of the CE board (Windows).

    python tools\build_share.py --src <folder holding scripts\> --name CE-Board-Copilot

The package contains a private Python 3.11 runtime and the scripts compiled to
bytecode (.pyc) only, so colleagues get a working tool without the .py source.
Bytecode is not encryption: it deters casual reading but a determined person
can still decompile it.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

VERSION = "3.11.9"
SHA256 = "009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b"
URL = ("https://www.python.org/ftp/python/{v}/python-{v}-embed-amd64.zip"
       .format(v=VERSION))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "build", "python-embed.zip")
NOTE = """CE Board

1. Unzip this folder anywhere.
2. Double-click Install.cmd.
3. Click Sign in on the page and use your Microsoft account.

Python is included; nothing else needs installing. Use the CE Board shortcut
on your Desktop afterwards.
"""


def fetch_runtime():
    if not os.path.exists(CACHE):
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        urllib.request.urlretrieve(URL, CACHE)
    with open(CACHE, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != SHA256:
            os.remove(CACHE)
            sys.exit("Runtime checksum mismatch")
    return CACHE


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=ROOT)
    ap.add_argument("--name", required=True)
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = ap.parse_args()

    dest = os.path.join(args.out, args.name)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    scripts = os.path.join(dest, "scripts")
    shutil.copytree(os.path.join(args.src, "scripts"), scripts,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with zipfile.ZipFile(fetch_runtime()) as z:
        z.extractall(os.path.join(dest, "runtime"))
    shutil.copy(os.path.join(ROOT, "Install.cmd"), dest)
    with open(os.path.join(dest, "README.txt"), "w") as fh:
        fh.write(NOTE)

    py = os.path.join(dest, "runtime", "python.exe")
    subprocess.check_call([py, "-m", "compileall", "-b", "-q", scripts])
    for name in os.listdir(scripts):
        if name.endswith(".py"):
            os.remove(os.path.join(scripts, name))

    archive = shutil.make_archive(dest, "zip", args.out, args.name)
    print("Built", archive)


if __name__ == "__main__":
    main()
