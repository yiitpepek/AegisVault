#!/usr/bin/env python3
"""PoC 06: emergency_zeroize_vault() sahte basari raporu / etkisiz imha.

Zafiyet: Silme dongusundeki tum hatalar 'except Exception: pass' ile yutulur; fonksiyon
her durumda True doner ve audit'e 'shredded' yazar. Ayrica yollar CWD'ye gore
cozuldugunden farkli dizinden calistirilirsa hicbir sey silinmez ama basari raporlanir.
"""
import os
import sys
import stat
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc06"
OTHER_CWD = "/tmp/opencode/aegis_poc/poc06_other"
shutil.rmtree(SANDBOX, ignore_errors=True)
shutil.rmtree(OTHER_CWD, ignore_errors=True)
os.makedirs(os.path.join(SANDBOX, "profiles"))
os.makedirs(OTHER_CWD)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import military_audit

VAULT = os.path.join(SANDBOX, "profiles", "victim.mvat")
CONTENT = "SIFRELI_KASA_ICERIGI_DEGISMEMELI"
with open(VAULT, "w", encoding="utf-8") as f:
    f.write(CONTENT)


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def last_zeroize_event():
    for e in military_audit.CryptographicAuditTrail.get_recent_events(10):
        if e["event_type"] == "EMERGENCY_ZEROIZE":
            return e
    return None


banner("PoC 06: 'DoD 5220.22-M imha tamamlandi' sahte raporu")

os.chmod(VAULT, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
print(f"[+] Kasa dosyasi salt-okunur yapildi (chmod 444): {VAULT}")

ret = military_audit.emergency_zeroize_vault("victim")
still_exists = os.path.exists(VAULT)
content_same = still_exists and open(VAULT, encoding="utf-8").read() == CONTENT
ev = last_zeroize_event()

print(f"\n[A] Fonksiyon donusu: {ret} (True = 'basarili imha')")
print(f"[A] Dosya hala diskte mi? {still_exists}")
print(f"[A] Icerik degismedi mi? {content_same}")
print(f"[A] Audit kaydi: {ev['details'] if ev else 'yok'}")

os.chmod(VAULT, stat.S_IRUSR | stat.S_IWUSR)
os.chdir(OTHER_CWD)
print(f"\n[+] Uygulama farkli bir CWD'den calistiriliyor: {os.getcwd()}")
ret2 = military_audit.emergency_zeroize_vault("victim")
still_exists2 = os.path.exists(VAULT)
ev2 = last_zeroize_event()

print(f"\n[B] Fonksiyon donusu: {ret2} (True = 'basarili imha')")
print(f"[B] Gercek kasa dosyasi hala diskte mi? {still_exists2}")
print(f"[B] Audit kaydi: {ev2['details'] if ev2 else 'yok'}")

print("\n" + "-" * 72)
print("KANIT: Hicbir bayt silinmeden 'DoD 5220.22-M imha tamamlandi' denip True donuyor.")
print("       Kullanici 'kasam imha edildi' sanirken tum sirlar diskte kaliyor.")
print("-" * 72)
