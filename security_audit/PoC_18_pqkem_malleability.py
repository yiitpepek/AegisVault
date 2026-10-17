#!/usr/bin/env python3
"""PoC 18 (W-02): Ozel PQ-Hybrid KEM'de CCA/FO donusumu ve girdi dogrulamasi yok.

FIPS 203 (ML-KEM) uyumlu bir KEM'de:
  - Kapsul (u,v) katsayilari aciKucluk/gecerlilik kontrollerinden gecer,
  - Cozme basarisizligi IMPLICIT REJECTION ile sahte-rastgele anahtara gider (hata sizdirilmaz),
  - Kapsul butunlugu anahtara baglanir (FO transformu: m = G(m' || H(ct))).
Bu uygulamada hicbiri yok:
  - decapsulate yalnizca LISTE UZUNLUGUNU kontrol eder (crypto_utils.py:367);
    katsayilar negatif/asin/huge/Nan olsa da kabul edilir,
  - veya u katsayisinda kucuk bir degisiklik anahtari SESSIZCE degistirir (hata yok),
  - u[0]=1e999 (inf) gibi degerler Nan yayip tum bitleri 0'a zorlar — yine hata yok.
Sonuc: protokolde anahtar dogrulamasi (key confirmation) olmadigindan, MITM'in
tek bayt degistirmesi taraflari sessizce farkli anahtarlara dusurur (desenkronizasyon DoS)
ve "AEAD kapsullu PQ el sikismasi" iddiasinin kriptografik butunlugu yoktur.
"""
import os
import sys
import json
import time
import base64
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc18"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

from crypto_utils import PQHybridKEM

CT_PREFIX = "AEGIS-PQCT-v1:"


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def decode_ct(ct_armored):
    return json.loads(base64.b64decode(ct_armored[len(CT_PREFIX):]).decode())


def encode_ct(obj):
    return CT_PREFIX + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


banner("PoC 18: Kapsul butunlugu ve katsayi dogrulamasi yok")

pk, sk = PQHybridKEM.generate_keypair()
ct, ss_sender = PQHybridKEM.encapsulate(pk)
ss_recv = PQHybridKEM.decapsulate(ct, sk)
print(f"[0] Normal akis: gonderen={ss_sender[:16]}... alici={ss_recv[:16]}... esit={ss_sender == ss_recv}")
assert ss_sender == ss_recv

print("\n[A] v[0] += 123 (1 katsayida kucuk degisiklik, MITM):")
obj_a = decode_ct(ct)
obj_a["v"] = list(obj_a["v"])
obj_a["v"][0] = (obj_a["v"][0] + 123) % 3329
try:
    ss_a = PQHybridKEM.decapsulate(encode_ct(obj_a), sk)
    print(f"    decapsulate HATA VERMEDI. Anahtar degisti mi? {ss_a != ss_recv}")
    print(f"    Yeni anahtar: {ss_a[:16]}... (taraflar sessizce ayristi, uyari yok)")
except Exception as e:
    print(f"    [beklenmiyordu] Hata: {e}")

print("\n[B] u[0] = 1e999 (inf) -> katsayi tipi/araligi dogrulanmiyor:")
obj_b = decode_ct(ct)
obj_b["u"] = list(obj_b["u"])
obj_b["u"][0] = 1e999
try:
    ss_b = PQHybridKEM.decapsulate(encode_ct(obj_b), sk)
    print(f"    decapsulate HATA VERMEDI. Anahtar: {ss_b[:16]}... (degisti mi? {ss_b != ss_recv})")
except Exception as e:
    print(f"    [beklenmiyordu] Hata: {e}")

print("\n[C] u katsayilari negatif ve >= q (3329) — yine kabul:")
obj_c = decode_ct(ct)
obj_c["u"] = list(obj_c["u"])
obj_c["u"][0] = -12345
obj_c["u"][1] = 999999
try:
    ss_c = PQHybridKEM.decapsulate(encode_ct(obj_c), sk)
    print(f"    decapsulate HATA VERMEDI. Anahtar: {ss_c[:16]}... (degisti mi? {ss_c != ss_recv})")
except Exception as e:
    print(f"    [beklenmiyordu] Hata: {e}")

print("\n[D] Deterministik sapma: ayni bozuk kapsul HER ZAMAN ayni anahtari uretir mi?")
ss_b2 = PQHybridKEM.decapsulate(encode_ct(obj_b), sk)
print(f"    ss_b == ss_b2 (ayni bozuk paket iki kez): {ss_b == ss_b2}")
print("    -> Saldirgan kapsulu nokta atisiyla degistirip taraflari O SECMEDIGI ama")
print("       deterministik bir anahtara kilitleyebilir; key-confirmation yoksa fark edilmez.")

print("\n[E] Kaynak: dogrulama yalnizca liste uzunlugu (crypto_utils.py:367):")
import inspect
src = inspect.getsource(PQHybridKEM.decapsulate)
for line in src.splitlines():
    if "len(" in line:
        print(f"    {line.strip()}")
print("    Katsayilar icin aralik/tip kontrolu YOK; ml-kem'deki gibi katsayi sikistirma")
print("    (compress/decompress) ve kapsul hash'leme (FO) adimlari da YOK.")

print("\n" + "-" * 72)
print("KANIT: [PQ-KEM-ACK] kapsulu butunluk dogrulamasi olmadan islenir; tek katsayi")
print("       degisikligi paylasilan anahtari sessizce degistirir. CCA-guvenligi (FIPS 203)")
print("       ve implicit rejection yok -> desenkronizasyon/replay-cercevesi zayiflatma.")
print("       Oneri: standart ML-KEM (liboqs/cryptography) kullanin; ara cozum olarak")
print("       katsayi araligi dogrulayin + ct'yi hash'e baglayan FO donusumu ekleyin.")
print("-" * 72)
