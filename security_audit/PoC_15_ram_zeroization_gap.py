#!/usr/bin/env python3
"""PoC 15 (V-18): 'RAM zeroization' sozlesme acigi (kismi kanit).

_zero_memory yalnizca bytearray'i sifirlar. Parola/duz metin yollarinin cogunda
Python str/bytes (immutable) kullanilir; bunlar sifirlanamaz. Ayrica encrypt()
duz metni once immutable bytes kopyasina, sonra da bytearray'e cevirir: yalnizca
son kopya sifirlanir. Fonksiyon sessizce no-op olur, hicbir hata vermez.
"""
import os
import sys
import shutil
import ctypes

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc15"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

from military_vault import MilitaryVault


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 15: _zero_memory sozlesmesi ve sifirlanamayan kopyalar")

pw_str = "S3cret-" + os.urandom(8).hex()
pw_bytes = pw_str.encode("utf-8")
pw_ba = bytearray(pw_bytes)

print(f"[1] Girdi turleri: str / bytes / bytearray")
MilitaryVault._zero_memory(pw_str)
MilitaryVault._zero_memory(pw_bytes)
MilitaryVault._zero_memory(pw_ba)
print(f"    str  _zero_memory sonrasi icerik : {pw_str!r}  (degismedi - str immutable)")
print(f"    bytes _zero_memory sonrasi icerik: {pw_bytes.decode()!r}  (degismedi - bytes immutable)")
print(f"    bytearray _zero_memory sonrasi   : {bytes(pw_ba)!r}  (yalnizca bu tur sifirlanabiliyor)")

print("\n[2] encrypt() akisi: duz metin 3 kopya olusturur, yalnizca sonuncusu sifirlanir")
print("    plaintext(str) -> plaintext.encode() [immutable bytes kopyasi, SIFIRLANMAZ]")
print("    -> bytes(plaintext_bytes) [AESGCM'e giden dahili kopya, SIFIRLANMAZ]")
print("    password(str) -> password_bytes=bytearray [yalnizca BU sifirlanir]")
ct = MilitaryVault.encrypt("Gizli seed: witch collapse practice", "Parola!123")
print(f"    Sifreleme tamam. Orijinal duz metin str nesnesi hala cagiran tarafta ve framework")
print(f"    tarafindan sifirlanmadi (immutable).")

print("\n[3] Canli bellek gozlemi (basit): ayni surecte az once kullanilan duz metin, GC'ye")
print("    birakilmadigi surece okunabilir kalir:")
secret = "Gizli seed: witch collapse practice"
raw = ctypes.string_at(id(secret), 128)
idx = raw.find(b"Gizli")
print(f"    str nesnesinin ham bellek bolgesinde duz metin bulundu mu? {idx >= 0} (offset ~{idx})")
if idx >= 0:
    print(f"    Okunan veri: {raw[idx:idx + 33]!r}")
print("    (Not: Bu, gercek bellek dökümü analizi degil; str nesnesinin surec icinde")
print("     sifirlanamaz oldugunun atif kanitidir. Forensic dump'lar icin daha agir kanit gerekir.)")

print("\n" + "-" * 72)
print("KANIT (kismi): _zero_memory str/bytes icin sessiz no-op; parola ve duz metin")
print("       kopyalari RAM'de kaliyor. README'deki 'RAM keys wiped / zeroized' iddiasi")
print("       yalnizca bytearray kopyalari icin dogrudur. Oneri: mumkun oldugunca kripto")
print("       nesnelerini mlock/kilitli bellek + 'cryptography' zeroize API'leri ile yonetin;")
print("       iddiayi gercege uygun revize edin.")
print("-" * 72)
