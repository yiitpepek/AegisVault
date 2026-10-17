#!/usr/bin/env python3
"""PoC 07: FIPS 140-3 POST (Power-On Self-Test) sonucu uygulanmiyor; basari logu sabit.

Zafiyet: app.py POST sonucunu yalnizca rozet rengi icin kullanir (satir 621-623) ve
satir 79-81'de testlerin sonucundan BAGIMSIZ olarak '100% Passed' audit kaydi atar.
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc07"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import military_audit


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 07: POST basarisizligi uygulanmiyor, audit'e sabit '100% Passed' yaziliyor")

military_audit.verify_runtime_backdoor_shield = lambda: (False, "SIMULE EDILEN KANIT TEKNI ARZASI")
result = military_audit.run_power_on_self_tests()
print(f"[1] run_power_on_self_tests() -> all_passed = {result['all_passed']}")
for t in result["tests"]:
    if not t["passed"]:
        print(f"    BASARISIZ: {t['name']} ({t['details']})")

military_audit.CryptographicAuditTrail.record_event(
    "POST_BOOT", "System", "FIPS 140-3 Power-On Self Tests 100% Passed (NIST KAT 100%)", "INFO"
)
ev = military_audit.CryptographicAuditTrail.get_recent_events(1)[0]
print(f"[2] app.py:79-81 birebir calistirildi -> audit kaydi: '{ev['details']}'")
print(f"    Gercek sonuc (all_passed=False) ile audit kaydi (100% Passed) CELISIYOR")

print("\n[3] app.py icindeki POST kullaniminin tamami:")
with open(os.path.join(PROJECT_DIR, "app.py"), encoding="utf-8") as f:
    lines = f.readlines()
for idx in (78, 79, 80, 81, 621, 622, 623):
    print(f"    app.py:{idx+1}: {lines[idx].rstrip()}")
print("    -> POST basarisiz olsa bile hicbir islem engellenmiyor; sadece rozet rengi degisir.")
print("    -> Ayrica 'True' varsayilan deger kullaniliyor: post_results yoksa da yesil rozet.")

print("\n" + "-" * 72)
print("KANIT: FIPS 140-3 'boot assurance' katmani kozmetik. Kriptografik cekirdek bozuk/arka")
print("       kapili olsa dahi uygulama sifreleme islemlerine aynen devam eder ve audit'e")
print("       '%100 gecti' yazar.")
print("-" * 72)
