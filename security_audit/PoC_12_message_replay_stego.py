#!/usr/bin/env python3
"""PoC 12 (V-16): decrypt_message() epoch/nonce dogrulamasi yapmiyor -> stego/QR replay.

Aciklama: Anti-replay mantigi yalnizca live_p2p_chat icinde; crypto_chat.decrypt_message
ve onu dogrudan cagiran steganografi + QR yollari yas dogrulamasi yapmaz. 6 yil eski
bir epoch ile hazirlanan mesaj ve ayni token'in sinirsiz tekrar kullanimi kabul edilir.
"""
import os
import sys
import json
import time
import shutil
import inspect
from PIL import Image

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc12"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)

import crypto_chat
from military_vault import MilitaryVault
import steganography

KEY = "Paylasilan-Parola!9"


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


banner("PoC 12: Mesaj katmaninda replay/yas dogrulamasi yok")

token = crypto_chat.encrypt_message("Bakiye transferi onayi", KEY)
p1 = crypto_chat.decrypt_message(token, KEY)
p2 = crypto_chat.decrypt_message(token, KEY)
p3 = crypto_chat.decrypt_message(token, KEY)
print(f"[1] Ayni token 3 kez cagrildi -> hepsi kabul edildi: {p1['text']!r}, {p2['text']!r}, {p3['text']!r}")
print("    (Bu katmanda nonce cache/yas kontrolu yok; tekrar oynatma tamamen cagirana bagli)")

old_env = {
    "text": "2020'DEN KALMA ESKI MESAJ",
    "timestamp": "2020-01-01 00:00:00",
    "nonce": "00" * 16,
    "epoch": 1577836800.0,
}
stale_token = "AEGIS-MSG-v1:" + MilitaryVault.encrypt(json.dumps(old_env), KEY)
stale = crypto_chat.decrypt_message(stale_token, KEY)
age_days = (time.time() - stale["epoch"]) / 86400
print(f"\n[2] 6 yil eski epoch ile hazirlanmis token kabul edildi: {stale['text']!r}")
print(f"    Yasi: {age_days:.0f} gun | Reddedildi mi? HAYIR")

print("\n[3] decrypt_message() kaynak kodu - hicbir epoch/nonce kontrolu yok:")
src = inspect.getsource(crypto_chat.decrypt_message)
for line in src.splitlines():
    if line.strip():
        print(f"    {line}")

print("\n[4] Cagri zinciri: stego/QR ayni fonksiyonu dogrudan cagiriyor (yas kontrolsuz):")
for fn in (steganography.extract_secret_from_image,):
    s = inspect.getsource(fn)
    for line in s.splitlines():
        if "decrypt_message" in line:
            print(f"    steganography.py: {line.strip()}")

cover = Image.new("RGB", (160, 160), (90, 120, 90))
cover.save("cover.png")
steganography.embed_secret_in_image("cover.png", "Replay edilebilir gizli mesaj", passkey=KEY, output_image_path="stego.png")
r1 = steganography.extract_secret_from_image("stego.png", passkey=KEY)
r2 = steganography.extract_secret_from_image("stego.png", passkey=KEY)
print(f"\n[5] Ayni stego PNG defalarca 'acildi': {r1!r} | {r2!r} | esit={r1 == r2}")
print("    -> Ele gecirilen bir gorsel/QR, anti-replay yakalanmadan yeniden oynatilabilir.")

print("\n" + "-" * 72)
print("KANIT: Yas/nonce dogrulamasi crypto_chat katmaninda YOK; tüm cagri yollari (P2P disi)")
print("       icin eski/yeniden paketler kabul ediliyor. Savunma 'cagirana birakilmis' ve")
print("       stego + QR cagirilari kontrol etmiyor.")
print("-" * 72)
