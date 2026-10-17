#!/usr/bin/env python3
"""PoC 16 (V-20): POST scrypt KAT'i uretim parametreleri yerine n=1024 test ediyor.

POST, 'scrypt KDF Determinist Testi' basligi altinda n=1024, r=8, p=1 kullanir;
uretim parametreleri ise log_n=15 (n=32768). Uretim parametreleriyle calisan KDF
bozuk olsa bile POST '100% gecer' - boot assurance katmani bunu yakalayamaz.
"""
import os
import sys
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc16"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import military_audit
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as RealScrypt
import military_vault


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 16: POST'un KDF testi uretim parametrelerini kapsamiyor")

captured = []


class SpyScrypt:
    def __init__(self, salt, length, n, r, p):
        captured.append({"n": n, "r": r, "p": p})
        self._impl = RealScrypt(salt=salt, length=length, n=n, r=r, p=p)

    def derive(self, key_material):
        return self._impl.derive(key_material)


military_audit.Scrypt = SpyScrypt
result = military_audit.run_power_on_self_tests()
military_audit.Scrypt = RealScrypt

print(f"[1] POST sirasinda kullanilan scrypt parametreleri: {captured}")
print(f"    Uretim varsayilani: log_n={military_vault.MilitaryVault.DEFAULT_LOG_N} "
      f"(n={1 << military_vault.MilitaryVault.DEFAULT_LOG_N}), r={military_vault.MilitaryVault.DEFAULT_R}, "
      f"p={military_vault.MilitaryVault.DEFAULT_P}")
print(f"    POST all_passed = {result['all_passed']}")

print("\n[2] 'Uretim parametrelerinde bozuk KDF' simule ediliyor (n>=32768 -> hata):")


class BrokenProductionScrypt:
    def __init__(self, salt, length, n, r, p):
        if n >= 32768:
            raise RuntimeError("SIMULE: uretim parametrelerinde KDF bozuk!")
        self._impl = RealScrypt(salt=salt, length=length, n=n, r=r, p=p)

    def derive(self, key_material):
        return self._impl.derive(key_material)


military_audit.Scrypt = BrokenProductionScrypt
result2 = military_audit.run_power_on_self_tests()
military_audit.Scrypt = RealScrypt
print(f"    POST sonucu: all_passed = {result2['all_passed']}  (bozuk uretim KDF'ine ragmen GECTI)")

military_vault.Scrypt = BrokenProductionScrypt
try:
    military_vault.MilitaryVault.encrypt("test", "parola")
    print("    [?] Uretim yolu calisti (beklenmiyordu)")
except RuntimeError as e:
    print(f"    Uretim yolu gercekten kirik: {e}")
finally:
    military_vault.Scrypt = RealScrypt

print("\n" + "-" * 72)
print("KANIT: FIPS POST'un KDF testi, uretimde fiilen kullanilan parametreleri (n=32768)")
print("       test etmedigi icin kriptografik cekirdekteki parametre regresyonlarini")
print("       yakalayamaz. Oneri: uretim parametreleriyle bilinen KAT vektoru dogrulayin;")
print("       boundary (log_n=10/20, r=1/32) degerlerini de test edin.")
print("-" * 72)
