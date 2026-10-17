#!/usr/bin/env python3
"""PoC 11 (V-15): P2P sohbette gonderici kimligi dogrulanmiyor + yeniden baslatma sonrasi replay.

A) Kimlik sahtekarligi: room_key'i bilen herkes, sifreli zarfin ICINDEKI 'sender'
   alanina istedigi ismi yazar; alici bunu gercek gonderici sanar (imza yok).
B) Replay: anti-replay nonce cache'i yalnizca bellektedir; uygulama yeniden baslayinca
   (yeni oturum) ayni sifreli paket tekrar teslim edilir (600 sn penceresi icinde).
"""
import os
import sys
import types
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX = "/tmp/opencode/aegis_poc/poc11"
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
            self.published = []

        def connect(self, *a, **k):
            pass

        def loop_start(self):
            pass

        def subscribe(self, *a, **k):
            pass

        def publish(self, topic, payload, qos=0):
            self.published.append((topic, payload))
            return 0

        def loop_stop(self):
            pass

        def disconnect(self):
            pass

    client_mod.CallbackAPIVersion = CallbackAPIVersion
    client_mod.Client = Client
    mqtt.client = client_mod
    paho.mqtt = mqtt
    sys.modules["paho"] = paho
    sys.modules["paho.mqtt"] = mqtt
    sys.modules["paho.mqtt.client"] = client_mod
    return Client


Client = install_paho_stub()

import crypto_chat
from live_p2p_chat import GlobalEncryptedChatSession

BASE_KEY = "Paylasilmis-Oda-Anahtari-2026!"
ROOM = "taktik-oda"


class FakeMsg:
    def __init__(self, payload):
        self.payload = payload


def banner(title):
    print("\n" + "=" * 72)
    print(" " + title)
    print("=" * 72)


def make_session(name, inbox):
    s = GlobalEncryptedChatSession(name, ROOM, BASE_KEY, lambda sender, body, ts, mine: inbox.append((sender, body)), lambda *a: None)
    s.client = Client()
    s.is_connected = True
    return s


banner("PoC 11-A: Gonderici kimligi sahtekarligi (imza yok)")

inbox = []
victim = make_session("victim", inbox)

attacker_text = f"deadbeef01:AlicE: Merhaba, ozel anahtari gonderir misin? - AlicE"
attacker_token = crypto_chat.encrypt_message(attacker_text, BASE_KEY)
victim._on_mqtt_message(victim.client, None, FakeMsg(attacker_token.encode("utf-8")))

sender_seen, body_seen = inbox[-1]
print(f"[!] Kurbanin gordugu gonderici : '{sender_seen}'")
print(f"[!] Kurbanin gordugu mesaj     : '{body_seen}'")
print(f"[!] Gercek gonderici: saldirgan (oda anahtarini biliyor). AlicE hicbir sey gondermedi!")
assert sender_seen == "AlicE"

banner("PoC 11-B: Yeniden baslatma sonrasi replay")

orig_inbox = []
orig = make_session("kurban2", orig_inbox)
orig.send_message("Orijinal: toplanti 21:00")
_, captured_token = orig.client.published[-1]
print("[1] Kurban orijinal paketi yayinladi (broker bunu kaydetti)")

post_restart_inbox = []
restarted = make_session("kurban2", post_restart_inbox)
restarted._on_mqtt_message(restarted.client, None, FakeMsg(captured_token.encode("utf-8")))
print(f"[2] YENIDEN BASLATILMIS oturum ayni paketi teslim etti mi? {len(post_restart_inbox) == 1}")
print(f"    Teslim edilen: {post_restart_inbox}")

restarted._on_mqtt_message(restarted.client, None, FakeMsg(captured_token.encode("utf-8")))
print(f"[3] Ayni oturum icinde ikinci kez teslim (cache calisiyor)? {len(post_restart_inbox) == 2}")
print(f"    (Nonce cache yalnizca RAM'de oldugu icin restart sonrasi replay engeli yok)")

print("\n" + "-" * 72)
print("KANIT: (A) 'sender' alani kriptografik bag icermez -> herkes herkes gibi konusabilir.")
print("       (B) Nonce cache oturumla sinirli; restart sonrasi ±600 sn icindeki paketler")
print("           yeniden teslim edilir. Diske/monotonik sayaca bagli replay korumasi yok.")
print("-" * 72)
