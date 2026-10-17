#!/usr/bin/env python3
"""PoC 14 (V-19): Unicode profil adi sanitizasyonu -> gorsel homoglif + sessiz dosya cakismasi.

get_profile_files(): safe_name = "".join(c for c in name if c.isalnum() or c in ("-","_"))
- str.isalnum() Unicode harfleri kabul eder -> Kiril 'А' ile 'Аtlas' != 'Atlas' ama gorsel ayni.
- Noktalama/Unicode disi karakterler SILINIR -> 'a.b' ile 'ab' AYNI dosyaya eslenir;
  ikinci profil olusturulunca birincinin kasasi sessizce UZERINE YAZILIR.
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc14"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import vault_storage as vs
from military_vault import VaultSecurityError


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 14: Profil adi cakismasi ve homoglif")

f1 = vs.get_profile_files("a.b")
f2 = vs.get_profile_files("ab")
print(f"[1] get_profile_files('a.b') -> {f1[0]}")
print(f"    get_profile_files('ab')  -> {f2[0]}")
print(f"    AYNI DOSYA MI? {f1[0] == f2[0]}")
assert f1[0] == f2[0]

vs.init_vault(master_password="BirinciKasa!2026", profile_name="a.b")
data1, _, _ = vs.unlock_vault("BirinciKasa!2026", profile_name="a.b")
print(f"\n[2] 'a.b' profili olusturuldu ve acildi (secret sayisi={len(data1.get('items', []))})")

vs.init_vault(master_password="IkinciKasa!2026", profile_name="ab")
print("[3] 'ab' profili olusturuldu (AYNI dosyanin uzerine yazildi)")

try:
    vs.unlock_vault("BirinciKasa!2026", profile_name="a.b")
    print("[?] Birinci kasa hala aciliyor (beklenmiyordu)")
except VaultSecurityError:
    print("[!] Birinci kasanin parolasi artik CALISMIYOR: 'a.b' profili sessizce yok edildi!")

data2, _, _ = vs.unlock_vault("IkinciKasa!2026", profile_name="ab")
print(f"[!] Dosyada kalan kasa: 'ab' profili (veri kaybi: 'a.b' icerigi gitti)")

h1 = "Аtlas"  # U+0410 Kiril А
h2 = "Atlas"
print(f"\n[4] Homoglif: {h1!r} vs {h2!r}")
print(f"    'Аtlas'.isalnum() icindeki her karakter kabul? {all(c.isalnum() or c in '-_' for c in h1)}")
print(f"    get_profile_files('{h1}') -> {vs.get_profile_files(h1)[0]}")
print(f"    get_profile_files('{h2}') -> {vs.get_profile_files(h2)[0]}")
print("    -> Gorsel olarak AYNI gorunen iki ayri kasa; adli/kullanici karisikligi")

print("\n" + "-" * 72)
print("KANIT: Sanitizasyon hem cakismaya (veri kaybi) hem homoglif karisikliga izin veriyor.")
print("       Oneri: NFKD normalize + ASCII [a-zA-Z0-9_-] whitelist + cakisma kontrolu")
print("       (olusturmadan once hedef dosya varsa hata ver).")
print("-" * 72)
